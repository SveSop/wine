/*
 * Process synchronisation
 *
 * Copyright 1996, 1997, 1998 Marcus Meissner
 * Copyright 1997, 1999 Alexandre Julliard
 * Copyright 1999, 2000 Juergen Schmied
 * Copyright 2003 Eric Pouech
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"
#include "wine/port.h"

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_POLL_H
#include <poll.h>
#endif
#ifdef HAVE_SYS_POLL_H
# include <sys/poll.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_SCHED_H
# include <sched.h>
#endif
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#ifdef __APPLE__
# include <mach/mach.h>
# include <mach/task.h>
# include <mach/semaphore.h>
# include <mach/mach_time.h>
#endif
#ifdef HAVE_LINUX_WINESYNC_H
# include <linux/winesync.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#define NONAMELESSUNION
#include "windef.h"
#include "winternl.h"
#include "ddk/wdm.h"
#include "wine/server.h"
#include "wine/exception.h"
#include "wine/debug.h"
#include "unix_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(sync);

HANDLE keyed_event = 0;

static const LARGE_INTEGER zero_timeout;

static pthread_mutex_t addr_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifndef __NR_clock_gettime64
#define __NR_clock_gettime64 403
#endif

struct timespec64
{
    __s64 tv_sec;
    __s64 tv_nsec;
};

static inline int do_clock_gettime( clockid_t clock_id, ULONGLONG *ticks )
{
    static int clock_gettime64_supported = -1;
    struct timespec64 ts64;
    struct timespec ts;
    int ret;

    if (clock_gettime64_supported < 0)
    {
        if (!syscall( __NR_clock_gettime64, clock_id, &ts64 ))
        {
            clock_gettime64_supported = 1;
            *ticks = ts64.tv_sec * (ULONGLONG)TICKSPERSEC + ts64.tv_nsec / 100;
            return 0;
        }
        clock_gettime64_supported = 0;
    }

    if (clock_gettime64_supported)
    {
        if (!(ret = syscall( __NR_clock_gettime64, clock_id, &ts64 )))
            *ticks = ts64.tv_sec * (ULONGLONG)TICKSPERSEC + ts64.tv_nsec / 100;
        return ret;
    }

    if (!(ret = clock_gettime( clock_id, &ts )))
        *ticks = ts.tv_sec * (ULONGLONG)TICKSPERSEC + ts.tv_nsec / 100;
    return ret;
}

/* return a monotonic time counter, in Win32 ticks */
static inline ULONGLONG monotonic_counter(void)
{
    struct timeval now;
#ifdef __APPLE__
    static mach_timebase_info_data_t timebase;

    if (!timebase.denom) mach_timebase_info( &timebase );
#ifdef HAVE_MACH_CONTINUOUS_TIME
    if (&mach_continuous_time != NULL)
        return mach_continuous_time() * timebase.numer / timebase.denom / 100;
#endif
    return mach_absolute_time() * timebase.numer / timebase.denom / 100;
#elif defined(HAVE_CLOCK_GETTIME)
    ULONGLONG ticks;
#if 0
    if (!do_clock_gettime( CLOCK_MONOTONIC_RAW, &ticks ))
        return ticks;
#endif
    if (!do_clock_gettime( CLOCK_MONOTONIC, &ticks ))
        return ticks;
#endif
    gettimeofday( &now, 0 );
    return ticks_from_time_t( now.tv_sec ) + now.tv_usec * 10 - server_start_time;
}


#ifdef __linux__

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_WAIT_BITSET 9
#define FUTEX_WAKE_BITSET 10

static int futex_private = 128;

static inline int futex_wait( const int *addr, int val, struct timespec *timeout )
{
    return syscall( __NR_futex, addr, FUTEX_WAIT | futex_private, val, timeout, 0, 0 );
}

static inline int futex_wake( const int *addr, int val )
{
    return syscall( __NR_futex, addr, FUTEX_WAKE | futex_private, val, NULL, 0, 0 );
}

static inline int futex_wait_bitset( const int *addr, int val, struct timespec *timeout, int mask )
{
    return syscall( __NR_futex, addr, FUTEX_WAIT_BITSET | futex_private, val, timeout, 0, mask );
}

static inline int futex_wake_bitset( const int *addr, int val, int mask )
{
    return syscall( __NR_futex, addr, FUTEX_WAKE_BITSET | futex_private, val, NULL, 0, mask );
}

static inline int use_futexes(void)
{
    static int supported = -1;

    if (supported == -1)
    {
        futex_wait( &supported, 10, NULL );
        if (errno == ENOSYS)
        {
            futex_private = 0;
            futex_wait( &supported, 10, NULL );
        }
        supported = (errno != ENOSYS);
    }
    return supported;
}

static int *get_futex(void **ptr)
{
    if (sizeof(void *) == 8)
        return (int *)((((ULONG_PTR)ptr) + 3) & ~3);
    else if (!(((ULONG_PTR)ptr) & 3))
        return (int *)ptr;
    else
        return NULL;
}

static void timespec_from_timeout( struct timespec *timespec, const LARGE_INTEGER *timeout )
{
    LARGE_INTEGER now;
    timeout_t diff;

    if (timeout->QuadPart > 0)
    {
        NtQuerySystemTime( &now );
        diff = timeout->QuadPart - now.QuadPart;
    }
    else
        diff = -timeout->QuadPart;

    timespec->tv_sec  = diff / TICKSPERSEC;
    timespec->tv_nsec = (diff % TICKSPERSEC) * 100;
}

#endif


static BOOL compare_addr( const void *addr, const void *cmp, SIZE_T size )
{
    switch (size)
    {
        case 1:
            return (*(const UCHAR *)addr == *(const UCHAR *)cmp);
        case 2:
            return (*(const USHORT *)addr == *(const USHORT *)cmp);
        case 4:
            return (*(const ULONG *)addr == *(const ULONG *)cmp);
        case 8:
            return (*(const ULONG64 *)addr == *(const ULONG64 *)cmp);
    }

    return FALSE;
}


static const char *debugstr_timeout( const LARGE_INTEGER *timeout )
{
    if (!timeout) return "<infinite>";
    return wine_dbg_sprintf( "%ld.%07ld", (long)timeout->QuadPart / TICKSPERSEC,
                             (long)timeout->QuadPart % TICKSPERSEC );
}


/* create a struct security_descriptor and contained information in one contiguous piece of memory */
NTSTATUS alloc_object_attributes( const OBJECT_ATTRIBUTES *attr, struct object_attributes **ret,
                                  data_size_t *ret_len )
{
    unsigned int len = sizeof(**ret);
    SID *owner = NULL, *group = NULL;
    ACL *dacl = NULL, *sacl = NULL;
    SECURITY_DESCRIPTOR *sd;

    *ret = NULL;
    *ret_len = 0;

    if (!attr) return STATUS_SUCCESS;

    if (attr->Length != sizeof(*attr)) return STATUS_INVALID_PARAMETER;

    if ((sd = attr->SecurityDescriptor))
    {
        len += sizeof(struct security_descriptor);
	if (sd->Revision != SECURITY_DESCRIPTOR_REVISION) return STATUS_UNKNOWN_REVISION;
        if (sd->Control & SE_SELF_RELATIVE)
        {
            SECURITY_DESCRIPTOR_RELATIVE *rel = (SECURITY_DESCRIPTOR_RELATIVE *)sd;
            if (rel->Owner) owner = (PSID)((BYTE *)rel + rel->Owner);
            if (rel->Group) group = (PSID)((BYTE *)rel + rel->Group);
            if ((sd->Control & SE_SACL_PRESENT) && rel->Sacl) sacl = (PSID)((BYTE *)rel + rel->Sacl);
            if ((sd->Control & SE_DACL_PRESENT) && rel->Dacl) dacl = (PSID)((BYTE *)rel + rel->Dacl);
        }
        else
        {
            owner = sd->Owner;
            group = sd->Group;
            if (sd->Control & SE_SACL_PRESENT) sacl = sd->Sacl;
            if (sd->Control & SE_DACL_PRESENT) dacl = sd->Dacl;
        }

        if (owner) len += offsetof( SID, SubAuthority[owner->SubAuthorityCount] );
        if (group) len += offsetof( SID, SubAuthority[group->SubAuthorityCount] );
        if (sacl) len += sacl->AclSize;
        if (dacl) len += dacl->AclSize;

        /* fix alignment for the Unicode name that follows the structure */
        len = (len + sizeof(WCHAR) - 1) & ~(sizeof(WCHAR) - 1);
    }

    if (attr->ObjectName)
    {
        if (attr->ObjectName->Length & (sizeof(WCHAR) - 1)) return STATUS_OBJECT_NAME_INVALID;
        len += attr->ObjectName->Length;
    }
    else if (attr->RootDirectory) return STATUS_OBJECT_NAME_INVALID;

    len = (len + 3) & ~3;  /* DWORD-align the entire structure */

    if (!(*ret = calloc( len, 1 ))) return STATUS_NO_MEMORY;

    (*ret)->rootdir = wine_server_obj_handle( attr->RootDirectory );
    (*ret)->attributes = attr->Attributes;

    if (attr->SecurityDescriptor)
    {
        struct security_descriptor *descr = (struct security_descriptor *)(*ret + 1);
        unsigned char *ptr = (unsigned char *)(descr + 1);

        descr->control = sd->Control & ~SE_SELF_RELATIVE;
        if (owner) descr->owner_len = offsetof( SID, SubAuthority[owner->SubAuthorityCount] );
        if (group) descr->group_len = offsetof( SID, SubAuthority[group->SubAuthorityCount] );
        if (sacl) descr->sacl_len = sacl->AclSize;
        if (dacl) descr->dacl_len = dacl->AclSize;

        memcpy( ptr, owner, descr->owner_len );
        ptr += descr->owner_len;
        memcpy( ptr, group, descr->group_len );
        ptr += descr->group_len;
        memcpy( ptr, sacl, descr->sacl_len );
        ptr += descr->sacl_len;
        memcpy( ptr, dacl, descr->dacl_len );
        (*ret)->sd_len = (sizeof(*descr) + descr->owner_len + descr->group_len + descr->sacl_len +
                          descr->dacl_len + sizeof(WCHAR) - 1) & ~(sizeof(WCHAR) - 1);
    }

    if (attr->ObjectName)
    {
        unsigned char *ptr = (unsigned char *)(*ret + 1) + (*ret)->sd_len;
        (*ret)->name_len = attr->ObjectName->Length;
        memcpy( ptr, attr->ObjectName->Buffer, (*ret)->name_len );
    }

    *ret_len = len;
    return STATUS_SUCCESS;
}


static NTSTATUS validate_open_object_attributes( const OBJECT_ATTRIBUTES *attr )
{
    if (!attr || attr->Length != sizeof(*attr)) return STATUS_INVALID_PARAMETER;

    if (attr->ObjectName)
    {
        if (attr->ObjectName->Length & (sizeof(WCHAR) - 1)) return STATUS_OBJECT_NAME_INVALID;
    }
    else if (attr->RootDirectory) return STATUS_OBJECT_NAME_INVALID;

    return STATUS_SUCCESS;
}


#ifdef HAVE_LINUX_WINESYNC_H

static int get_fast_sync_device(void)
{
    static int fast_sync_fd = -2;

    if (fast_sync_fd == -2)
    {
        HANDLE device;
        int fd, needs_close;
        NTSTATUS ret;

        SERVER_START_REQ( get_fast_sync_device )
        {
            if (!(ret = wine_server_call( req ))) device = wine_server_ptr_handle( reply->handle );
        }
        SERVER_END_REQ;

        if (!ret)
        {
            if (!server_get_unix_fd( device, 0, &fd, &needs_close, NULL, NULL ))
            {
                if (InterlockedCompareExchange( &fast_sync_fd, fd, -2 ) != -2)
                {
                    /* someone beat us to it */
                    if (needs_close) close( fd );
                    NtClose( device );
                }
                /* otherwise don't close the device */
            }
            else
            {
                InterlockedCompareExchange( &fast_sync_fd, -1, -2 );
                NtClose( device );
            }
        }
        else
        {
            InterlockedCompareExchange( &fast_sync_fd, -1, -2 );
        }
    }
    return fast_sync_fd;
}

/* It's possible for synchronization primitives to remain alive even after being
 * closed, because a thread is still waiting on them. It's rare in practice, and
 * documented as being undefined behaviour by Microsoft, but it works, and some
 * applications rely on it. This means we need to refcount handles, and defer
 * deleting them on the server side until the refcount reaches zero. We do this
 * by having each client process hold a handle to the fast synchronization
 * object, as well as a private refcount. When the client refcount reaches zero,
 * it closes the handle; when all handles are closed, the server deletes the
 * fast synchronization object.
 *
 * We want lookup of objects from the cache to be very fast; ideally, it should
 * be lock-free. We achieve this by using atomic modifications to "refcount",
 * and guaranteeing that all other fields are valid and correct *as long as*
 * refcount is nonzero, and we store the entire structure in memory which will
 * never be freed.
 *
 * This means that acquiring the object can't use a simple atomic increment; it
 * has to use a compare-and-swap loop to ensure that it doesn't try to increment
 * an object with a zero refcount. That's still leagues better than a real lock,
 * though, and release can be a single atomic decrement.
 *
 * It also means that threads modifying the cache need to take a lock, to
 * prevent other threads from writing to it concurrently.
 *
 * It's possible for an object currently in use (by a waiter) to be closed and
 * the same handle immediately reallocated to a different object. This should be
 * a very rare situation, and in that case we simply don't cache the handle.
 */
struct fast_sync_cache_entry
{
    LONG refcount;
    unsigned int obj;
    enum fast_sync_type type;
    unsigned int access;
    BOOL closed;
    /* handle to the underlying fast sync object, stored as obj_handle_t to save
     * space */
    obj_handle_t handle;
};


static void release_fast_sync_obj( struct fast_sync_cache_entry *cache )
{
    /* save the handle now; as soon as the refcount hits 0 we cannot access the
     * cache anymore */
    HANDLE handle = wine_server_ptr_handle( cache->handle );
    LONG refcount = InterlockedDecrement( &cache->refcount );

    assert( refcount >= 0 );

    if (!refcount)
    {
        NTSTATUS ret = NtClose( handle );
        assert( !ret );
    }
}


/* returns a pointer to a cache entry; if the object could not be cached,
 * returns "stack_cache" instead, which should be allocated on stack */
static NTSTATUS get_fast_sync_obj( HANDLE handle, enum fast_sync_type desired_type, ACCESS_MASK desired_access,
                                   struct fast_sync_cache_entry *stack_cache,
                                   struct fast_sync_cache_entry **ret_cache )
{
    struct fast_sync_cache_entry *cache = stack_cache;
    NTSTATUS ret;

    *ret_cache = stack_cache;

    SERVER_START_REQ( get_fast_sync_obj )
    {
        req->handle = wine_server_obj_handle( handle );
        if (!(ret = wine_server_call( req )))
        {
            cache->handle = reply->handle;
            cache->access = reply->access;
            cache->type = reply->type;
            cache->obj = reply->obj;
            cache->refcount = 1;
            cache->closed = FALSE;
        }
    }
    SERVER_END_REQ;

    if (!ret && desired_type && desired_type != cache->type)
    {
        release_fast_sync_obj( cache );
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    if (!ret && (cache->access & desired_access) != desired_access)
    {
        release_fast_sync_obj( cache );
        return STATUS_ACCESS_DENIED;
    }

    return ret;
}


static NTSTATUS fast_release_semaphore_obj( int device, unsigned int obj, ULONG count, ULONG *prev_count )
{
    struct winesync_sem_args args = {0};
    NTSTATUS ret;

    args.sem = obj;
    args.count = count;
    ret = ioctl( device, WINESYNC_IOC_PUT_SEM, &args );
    if (ret < 0)
    {
        if (errno == EOVERFLOW)
            return STATUS_SEMAPHORE_LIMIT_EXCEEDED;
        else
            return errno_to_status( errno );
    }
    if (prev_count) *prev_count = args.count;
    return STATUS_SUCCESS;
}


static NTSTATUS fast_release_semaphore( HANDLE handle, ULONG count, ULONG *prev_count )
{
    struct fast_sync_cache_entry stack_cache, *cache;
    NTSTATUS ret;
    int device;

    if ((device = get_fast_sync_device()) < 0)
        return STATUS_NOT_IMPLEMENTED;

    if ((ret = get_fast_sync_obj( handle, FAST_SYNC_SEMAPHORE,
                                  SEMAPHORE_MODIFY_STATE, &stack_cache, &cache )))
        return ret;

    ret = fast_release_semaphore_obj( device, cache->obj, count, prev_count );

    release_fast_sync_obj( cache );
    return ret;
}


static NTSTATUS fast_query_semaphore_obj( int device, unsigned int obj, SEMAPHORE_BASIC_INFORMATION *info )
{
    struct winesync_sem_args args = {0};
    NTSTATUS ret;

    args.sem = obj;
    ret = ioctl( device, WINESYNC_IOC_READ_SEM, &args );

    if (ret < 0)
        return errno_to_status( errno );
    info->CurrentCount = args.count;
    info->MaximumCount = args.max;
    return STATUS_SUCCESS;
}


static NTSTATUS fast_query_semaphore( HANDLE handle, SEMAPHORE_BASIC_INFORMATION *info )
{
    struct fast_sync_cache_entry stack_cache, *cache;
    NTSTATUS ret;
    int device;

    if ((device = get_fast_sync_device()) < 0)
        return STATUS_NOT_IMPLEMENTED;

    if ((ret = get_fast_sync_obj( handle, FAST_SYNC_SEMAPHORE,
                                  SEMAPHORE_QUERY_STATE, &stack_cache, &cache )))
        return ret;

    ret = fast_query_semaphore_obj( device, cache->obj, info );

    release_fast_sync_obj( cache );
    return ret;
}


static NTSTATUS fast_set_event_obj( int device, unsigned int obj, LONG *prev_state )
{
    struct winesync_sem_args args = {0};
    NTSTATUS ret;

    args.sem = obj;
    args.count = 1;
    ret = ioctl( device, WINESYNC_IOC_PUT_SEM, &args );
    if (ret < 0)
    {
        if (errno == EOVERFLOW)
        {
            if (prev_state) *prev_state = 1;
            return STATUS_SUCCESS;
        }
        else
            return errno_to_status( errno );
    }
    if (prev_state) *prev_state = 0;
    return STATUS_SUCCESS;
}


static NTSTATUS fast_set_event( HANDLE handle, LONG *prev_state )
{
    struct fast_sync_cache_entry stack_cache, *cache;
    NTSTATUS ret;
    int device;

    if ((device = get_fast_sync_device()) < 0)
        return STATUS_NOT_IMPLEMENTED;

    if ((ret = get_fast_sync_obj( handle, FAST_SYNC_EVENT, EVENT_MODIFY_STATE,
                                  &stack_cache, &cache )))
        return ret;

    ret = fast_set_event_obj( device, cache->obj, prev_state );

    release_fast_sync_obj( cache );
    return ret;
}


static NTSTATUS fast_reset_event_obj( int device, unsigned int obj, LONG *prev_state )
{
    NTSTATUS ret;

    ret = ioctl( device, WINESYNC_IOC_GET_SEM, &obj );
    if (ret < 0)
    {
        if (errno == EWOULDBLOCK)
        {
            if (prev_state) *prev_state = 0;
            return STATUS_SUCCESS;
        }
        else
            return errno_to_status( errno );
    }
    if (prev_state) *prev_state = 1;
    return STATUS_SUCCESS;
}


static NTSTATUS fast_reset_event( HANDLE handle, LONG *prev_state )
{
    struct fast_sync_cache_entry stack_cache, *cache;
    NTSTATUS ret;
    int device;

    if ((device = get_fast_sync_device()) < 0)
        return STATUS_NOT_IMPLEMENTED;

    if ((ret = get_fast_sync_obj( handle, FAST_SYNC_EVENT, EVENT_MODIFY_STATE,
                                  &stack_cache, &cache )))
        return ret;

    ret = fast_reset_event_obj( device, cache->obj, prev_state );

    release_fast_sync_obj( cache );
    return ret;
}


static NTSTATUS fast_pulse_event_obj( int device, unsigned int obj, LONG *prev_state )
{
    struct winesync_sem_args args = {0};
    NTSTATUS ret;

    args.sem = obj;
    args.count = 1;
    ret = ioctl( device, WINESYNC_IOC_PULSE_SEM, &args );
    if (ret < 0)
    {
        if (errno == EOVERFLOW)
        {
            if (prev_state) *prev_state = 1;
            return STATUS_SUCCESS;
        }
        else
            return errno_to_status( errno );
    }
    if (prev_state) *prev_state = 0;
    return STATUS_SUCCESS;
}


static NTSTATUS fast_pulse_event( HANDLE handle, LONG *prev_state )
{
    struct fast_sync_cache_entry stack_cache, *cache;
    NTSTATUS ret;
    int device;

    if ((device = get_fast_sync_device()) < 0)
        return STATUS_NOT_IMPLEMENTED;

    if ((ret = get_fast_sync_obj( handle, FAST_SYNC_EVENT, EVENT_MODIFY_STATE,
                                  &stack_cache, &cache )))
        return ret;

    ret = fast_pulse_event_obj( device, cache->obj, prev_state );

    release_fast_sync_obj( cache );
    return ret;
}


static NTSTATUS fast_query_event_obj( int device, unsigned int obj, EVENT_BASIC_INFORMATION *info )
{
    struct winesync_sem_args args = {0};
    NTSTATUS ret;

    args.sem = obj;
    ret = ioctl( device, WINESYNC_IOC_READ_SEM, &args );

    if (ret < 0)
        return errno_to_status( errno );
    info->EventType = (args.flags & WINESYNC_SEM_GETONWAIT) ? SynchronizationEvent : NotificationEvent;
    info->EventState = args.count;
    return STATUS_SUCCESS;
}


static NTSTATUS fast_query_event( HANDLE handle, EVENT_BASIC_INFORMATION *info )
{
    struct fast_sync_cache_entry stack_cache, *cache;
    NTSTATUS ret;
    int device;

    if ((device = get_fast_sync_device()) < 0)
        return STATUS_NOT_IMPLEMENTED;

    if ((ret = get_fast_sync_obj( handle, FAST_SYNC_EVENT, EVENT_QUERY_STATE,
                                  &stack_cache, &cache )))
        return ret;

    ret = fast_query_event_obj( device, cache->obj, info );

    release_fast_sync_obj( cache );
    return ret;
}


static NTSTATUS fast_release_mutex_obj( int device, unsigned int obj, LONG *prev_count )
{
    struct winesync_mutex_args args = {0};
    NTSTATUS ret;

    args.mutex = obj;
    args.owner = GetCurrentThreadId();
    ret = ioctl( device, WINESYNC_IOC_PUT_MUTEX, &args );

    if (ret < 0)
    {
        if (errno == EOVERFLOW)
            return STATUS_MUTANT_LIMIT_EXCEEDED;
        else if (errno == EPERM)
            return STATUS_MUTANT_NOT_OWNED;
        else
            return errno_to_status( errno );
    }
    if (prev_count) *prev_count = 1 - args.count;
    return STATUS_SUCCESS;
}


static NTSTATUS fast_release_mutex( HANDLE handle, LONG *prev_count )
{
    struct fast_sync_cache_entry stack_cache, *cache;
    NTSTATUS ret;
    int device;

    if ((device = get_fast_sync_device()) < 0)
        return STATUS_NOT_IMPLEMENTED;

    if ((ret = get_fast_sync_obj( handle, FAST_SYNC_MUTEX, 0, &stack_cache, &cache )))
        return ret;

    ret = fast_release_mutex_obj( device, cache->obj, prev_count );

    release_fast_sync_obj( cache );
    return ret;
}


static NTSTATUS fast_query_mutex_obj( int device, unsigned int obj, MUTANT_BASIC_INFORMATION *info )
{
    struct winesync_mutex_args args = {0};
    NTSTATUS ret;

    args.mutex = obj;
    ret = ioctl( device, WINESYNC_IOC_READ_MUTEX, &args );

    if (ret < 0)
    {
        if (errno == EOWNERDEAD)
        {
            info->AbandonedState = TRUE;
            info->OwnedByCaller = FALSE;
            info->CurrentCount = 1;
            return STATUS_SUCCESS;
        }
        else
            return errno_to_status( errno );
    }
    info->AbandonedState = FALSE;
    info->OwnedByCaller = (args.owner == GetCurrentThreadId());
    info->CurrentCount = 1 - args.count;
    return STATUS_SUCCESS;
}


static NTSTATUS fast_query_mutex( HANDLE handle, MUTANT_BASIC_INFORMATION *info )
{
    struct fast_sync_cache_entry stack_cache, *cache;
    NTSTATUS ret;
    int device;

    if ((device = get_fast_sync_device()) < 0)
        return STATUS_NOT_IMPLEMENTED;

    if ((ret = get_fast_sync_obj( handle, FAST_SYNC_MUTEX, MUTANT_QUERY_STATE,
                                  &stack_cache, &cache )))
        return ret;

    ret = fast_query_mutex_obj( device, cache->obj, info );

    release_fast_sync_obj( cache );
    return ret;
}

static void timespec64_from_timeout( struct timespec64 *timespec, const LARGE_INTEGER *timeout )
{
    struct timespec now;
    timeout_t relative;

    clock_gettime( CLOCK_MONOTONIC, &now );

    if (timeout->QuadPart <= 0)
    {
        relative = -timeout->QuadPart;
    }
    else
    {
        LARGE_INTEGER system_now;

        /* the system clock is probably REALTIME, so we need to convert to
         * relative time first */
        NtQuerySystemTime( &system_now );
        relative = timeout->QuadPart - system_now.QuadPart;
    }

    timespec->tv_sec = now.tv_sec + (relative / TICKSPERSEC);
    timespec->tv_nsec = now.tv_nsec + ((relative % TICKSPERSEC) * 100);
    if (timespec->tv_nsec >= 1000000000)
    {
        timespec->tv_nsec -= 1000000000;
        ++timespec->tv_sec;
    }
}

static void select_queue( HANDLE queue )
{
    SERVER_START_REQ( fast_select_queue )
    {
        req->handle = wine_server_obj_handle( queue );
        wine_server_call( req );
    }
    SERVER_END_REQ;
}

static void unselect_queue( HANDLE queue, BOOL signaled )
{
    SERVER_START_REQ( fast_unselect_queue )
    {
        req->handle = wine_server_obj_handle( queue );
        req->signaled = signaled;
        wine_server_call( req );
    }
    SERVER_END_REQ;
}

static NTSTATUS fast_wait_objs( int device, DWORD count, const unsigned int *objs, BOOLEAN wait_any,
                                BOOLEAN alertable, const LARGE_INTEGER *timeout, user_apc_t *apc )
{
    volatile struct winesync_wait_args args = {0};
    struct timespec64 timespec;
    uintptr_t timeout_ptr = 0;
    unsigned long request;
    NTSTATUS ret;

    if (timeout && timeout->QuadPart != TIMEOUT_INFINITE)
    {
        timeout_ptr = (uintptr_t)&timespec;
        timespec64_from_timeout( &timespec, timeout );
    }
    args.objs = (uintptr_t)objs;
    args.count = count;
    args.owner = GetCurrentThreadId();
    args.index = ~0u;

    if (wait_any || count == 1)
        request = WINESYNC_IOC_WAIT_ANY;
    else
        request = WINESYNC_IOC_WAIT_ALL;

    if (alertable)
    {
        struct timespec64 now64;
        struct timespec now;

        /* if there is an already signaled object and an APC available, the
         * object is returned first */
        clock_gettime( CLOCK_MONOTONIC, &now );
        now64.tv_sec = now.tv_sec;
        now64.tv_nsec = now.tv_nsec;
        args.timeout = (uintptr_t)&now64;
        do
        {
            ret = ioctl( device, request, &args );
        } while (ret < 0 && errno == EINTR);

        if (ret < 0 && errno == ETIMEDOUT)
        {
            args.timeout = timeout_ptr;

            /* When a user APC is queued to this thread, the server wakes us
             * with SIGUSR1, whereupon usr1_handler() will longjmp here, causing
             * us to poll for a user APC again. It's not enough simply to retry
             * on EINTR, as we might get SIGUSR1 after checking for user APCs
             * but before calling ioctl(). */

            sigsetjmp( ntdll_get_thread_data()->fast_alert_buf, 1 );

            /* If the signal arrives *after* the ioctl, and the wait succeeded,
             * we don't want to wait again. */

            if (args.index != ~0u)
            {
                ntdll_get_thread_data()->in_fast_alert_wait = 0;
                ret = 0;
                goto out;
            }

            ntdll_get_thread_data()->in_fast_alert_wait = 1;

            SERVER_START_REQ( check_user_apc )
            {
                ret = wine_server_call( req );
            }
            SERVER_END_REQ;

            if (!ret)
            {
                ntdll_get_thread_data()->in_fast_alert_wait = 0;

                /* Retrieve the user APC. We can't actually dequeue it until
                 * after we reset in_fast_alert_wait, as otherwise we could
                 * have the thread context changed on us and drop the APC data
                 * on the floor. */
                ret = server_select( NULL, 0, SELECT_INTERRUPTIBLE | SELECT_ALERTABLE,
                                     0, NULL, NULL, apc );
                assert( ret == STATUS_USER_APC );
                return ret;
            }

            do
            {
                ret = ioctl( device, request, &args );
            } while (ret < 0 && errno == EINTR);

            ntdll_get_thread_data()->in_fast_alert_wait = 0;
        }
    }
    else
    {
        args.timeout = timeout_ptr;
        do
        {
            ret = ioctl( device, request, &args );
        } while (ret < 0 && errno == EINTR);
    }

out:
    if (!ret)
        return wait_any ? args.index : 0;
    else if (errno == EOWNERDEAD)
        return STATUS_ABANDONED + (wait_any ? args.index : 0);
    else if (errno == ETIMEDOUT)
        return STATUS_TIMEOUT;
    else
        return errno_to_status( errno );
}

static NTSTATUS fast_wait( DWORD count, const HANDLE *handles, BOOLEAN wait_any,
                           BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    struct fast_sync_cache_entry stack_cache[64], *cache[64];
    unsigned int objs[64];
    HANDLE queue = NULL;
    user_apc_t apc;
    NTSTATUS ret;
    DWORD i, j;
    int device;

    if ((device = get_fast_sync_device()) < 0)
        return STATUS_NOT_IMPLEMENTED;

    for (i = 0; i < count; ++i)
    {
        if ((ret = get_fast_sync_obj( handles[i], 0, SYNCHRONIZE, &stack_cache[i], &cache[i] )))
        {
            for (j = 0; j < i; ++j)
                release_fast_sync_obj( cache[j] );
            return ret;
        }
        if (cache[i]->type == FAST_SYNC_QUEUE)
            queue = handles[i];

        objs[i] = cache[i]->obj;
    }

    if (queue) select_queue( queue );

    ret = fast_wait_objs( device, count, objs, wait_any, alertable, timeout, &apc );

    if (queue) unselect_queue( queue, handles[ret] == queue );

    for (i = 0; i < count; ++i)
        release_fast_sync_obj( cache[i] );

    if (ret == STATUS_USER_APC)
        invoke_user_apc( NULL, &apc, ret );
    return ret;
}

static NTSTATUS fast_signal_and_wait( HANDLE signal, HANDLE wait,
                                      BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    struct fast_sync_cache_entry signal_stack_cache, *signal_cache;
    struct fast_sync_cache_entry wait_stack_cache, *wait_cache;
    HANDLE queue = NULL;
    user_apc_t apc;
    NTSTATUS ret;
    int device;

    if ((device = get_fast_sync_device()) < 0)
        return STATUS_NOT_IMPLEMENTED;

    if ((ret = get_fast_sync_obj( signal, 0, 0, &signal_stack_cache, &signal_cache )))
        return ret;

    switch (signal_cache->type)
    {
        case FAST_SYNC_SEMAPHORE:
            if (!(signal_cache->access & SEMAPHORE_MODIFY_STATE))
            {
                release_fast_sync_obj( signal_cache );
                return STATUS_ACCESS_DENIED;
            }
            break;

        case FAST_SYNC_EVENT:
            if (!(signal_cache->access & EVENT_MODIFY_STATE))
            {
                release_fast_sync_obj( signal_cache );
                return STATUS_ACCESS_DENIED;
            }
            break;

        case FAST_SYNC_MUTEX:
            break;

        default:
            /* can't be signaled */
            release_fast_sync_obj( signal_cache );
            return STATUS_OBJECT_TYPE_MISMATCH;
    }

    if ((ret = get_fast_sync_obj( wait, 0, SYNCHRONIZE, &wait_stack_cache, &wait_cache )))
    {
        release_fast_sync_obj( signal_cache );
        return ret;
    }

    if (wait_cache->type == FAST_SYNC_QUEUE)
        queue = wait;

    switch (signal_cache->type)
    {
        case FAST_SYNC_SEMAPHORE:
            ret = fast_release_semaphore_obj( device, signal_cache->obj, 1, NULL );
            break;

        case FAST_SYNC_EVENT:
            ret = fast_set_event_obj( device, signal_cache->obj, NULL );
            break;

        case FAST_SYNC_MUTEX:
            ret = fast_release_mutex_obj( device, signal_cache->obj, NULL );
            break;

        default:
            assert( 0 );
            break;
    }

    if (!ret)
    {
        if (queue) select_queue( queue );

        ret = fast_wait_objs( device, 1, &wait_cache->obj, TRUE, alertable, timeout, &apc );

        if (queue) unselect_queue( queue, !ret );
    }

    release_fast_sync_obj( signal_cache );
    release_fast_sync_obj( wait_cache );

    if (ret == STATUS_USER_APC)
        invoke_user_apc( NULL, &apc, ret );
    return ret;
}

#else

static NTSTATUS fast_release_semaphore( HANDLE handle, ULONG count, ULONG *prev_count )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS fast_query_semaphore( HANDLE handle, SEMAPHORE_BASIC_INFORMATION *info )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS fast_set_event( HANDLE handle, LONG *prev_state )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS fast_reset_event( HANDLE handle, LONG *prev_state )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS fast_pulse_event( HANDLE handle, LONG *prev_state )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS fast_query_event( HANDLE handle, EVENT_BASIC_INFORMATION *info )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS fast_release_mutex( HANDLE handle, LONG *prev_count )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS fast_query_mutex( HANDLE handle, MUTANT_BASIC_INFORMATION *info )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS fast_wait( DWORD count, const HANDLE *handles, BOOLEAN wait_any,
                           BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS fast_signal_and_wait( HANDLE signal, HANDLE wait,
                                      BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    return STATUS_NOT_IMPLEMENTED;
}

#endif


/******************************************************************************
 *              NtCreateSemaphore (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateSemaphore( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                   LONG initial, LONG max )
{
    NTSTATUS ret;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE( "access %#x, name %s, initial %d, max %d\n", access,
           attr ? debugstr_us(attr->ObjectName) : "(null)", initial, max );

    if (max <= 0 || initial < 0 || initial > max) return STATUS_INVALID_PARAMETER;
    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_semaphore )
    {
        req->access  = access;
        req->initial = initial;
        req->max     = max;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return ret;
}


/******************************************************************************
 *              NtOpenSemaphore (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenSemaphore( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS ret;

    TRACE( "access %#x, name %s\n", access, attr ? debugstr_us(attr->ObjectName) : "(null)" );

    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_semaphore )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtQuerySemaphore (NTDLL.@)
 */
NTSTATUS WINAPI NtQuerySemaphore( HANDLE handle, SEMAPHORE_INFORMATION_CLASS class,
                                  void *info, ULONG len, ULONG *ret_len )
{
    NTSTATUS ret;
    SEMAPHORE_BASIC_INFORMATION *out = info;

    TRACE("(%p, %u, %p, %u, %p)\n", handle, class, info, len, ret_len);

    if (class != SemaphoreBasicInformation)
    {
        FIXME("(%p,%d,%u) Unknown class\n", handle, class, len);
        return STATUS_INVALID_INFO_CLASS;
    }

    if (len != sizeof(SEMAPHORE_BASIC_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;

    if ((ret = fast_query_semaphore( handle, out )) != STATUS_NOT_IMPLEMENTED)
    {
        if (!ret && ret_len) *ret_len = sizeof(SEMAPHORE_BASIC_INFORMATION);
        return ret;
    }

    SERVER_START_REQ( query_semaphore )
    {
        req->handle = wine_server_obj_handle( handle );
        if (!(ret = wine_server_call( req )))
        {
            out->CurrentCount = reply->current;
            out->MaximumCount = reply->max;
            if (ret_len) *ret_len = sizeof(SEMAPHORE_BASIC_INFORMATION);
        }
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtReleaseSemaphore (NTDLL.@)
 */
NTSTATUS WINAPI NtReleaseSemaphore( HANDLE handle, ULONG count, ULONG *previous )
{
    NTSTATUS ret;

    TRACE( "handle %p, count %u, prev_count %p\n", handle, count, previous );

    if ((ret = fast_release_semaphore( handle, count, previous )) != STATUS_NOT_IMPLEMENTED)
        return ret;

    SERVER_START_REQ( release_semaphore )
    {
        req->handle = wine_server_obj_handle( handle );
        req->count  = count;
        if (!(ret = wine_server_call( req )))
        {
            if (previous) *previous = reply->prev_count;
        }
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *              NtCreateEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateEvent( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                               EVENT_TYPE type, BOOLEAN state )
{
    NTSTATUS ret;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE( "access %#x, name %s, type %u, state %u\n", access,
           attr ? debugstr_us(attr->ObjectName) : "(null)", type, state );

    if (type != NotificationEvent && type != SynchronizationEvent) return STATUS_INVALID_PARAMETER;
    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_event )
    {
        req->access = access;
        req->manual_reset = (type == NotificationEvent);
        req->initial_state = state;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return ret;
}


/******************************************************************************
 *              NtOpenEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenEvent( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS ret;

    TRACE( "access %#x, name %s\n", access, attr ? debugstr_us(attr->ObjectName) : "(null)" );

    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_event )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtSetEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtSetEvent( HANDLE handle, LONG *prev_state )
{
    NTSTATUS ret;

    TRACE( "handle %p, prev_state %p\n", handle, prev_state );

    if ((ret = fast_set_event( handle, prev_state )) != STATUS_NOT_IMPLEMENTED)
        return ret;

    SERVER_START_REQ( event_op )
    {
        req->handle = wine_server_obj_handle( handle );
        req->op     = SET_EVENT;
        ret = wine_server_call( req );
        if (!ret && prev_state) *prev_state = reply->state;
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtResetEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtResetEvent( HANDLE handle, LONG *prev_state )
{
    NTSTATUS ret;

    TRACE( "handle %p, prev_state %p\n", handle, prev_state );

    if ((ret = fast_reset_event( handle, prev_state )) != STATUS_NOT_IMPLEMENTED)
        return ret;

    SERVER_START_REQ( event_op )
    {
        req->handle = wine_server_obj_handle( handle );
        req->op     = RESET_EVENT;
        ret = wine_server_call( req );
        if (!ret && prev_state) *prev_state = reply->state;
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtClearEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtClearEvent( HANDLE handle )
{
    /* FIXME: same as NtResetEvent ??? */
    return NtResetEvent( handle, NULL );
}


/******************************************************************************
 *              NtPulseEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtPulseEvent( HANDLE handle, LONG *prev_state )
{
    NTSTATUS ret;

    TRACE( "handle %p, prev_state %p\n", handle, prev_state );

    if ((ret = fast_pulse_event( handle, prev_state )) != STATUS_NOT_IMPLEMENTED)
        return ret;

    SERVER_START_REQ( event_op )
    {
        req->handle = wine_server_obj_handle( handle );
        req->op     = PULSE_EVENT;
        ret = wine_server_call( req );
        if (!ret && prev_state) *prev_state = reply->state;
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtQueryEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryEvent( HANDLE handle, EVENT_INFORMATION_CLASS class,
                              void *info, ULONG len, ULONG *ret_len )
{
    NTSTATUS ret;
    EVENT_BASIC_INFORMATION *out = info;

    TRACE("(%p, %u, %p, %u, %p)\n", handle, class, info, len, ret_len);

    if (class != EventBasicInformation)
    {
        FIXME("(%p, %d, %d) Unknown class\n",
              handle, class, len);
        return STATUS_INVALID_INFO_CLASS;
    }

    if (len != sizeof(EVENT_BASIC_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;

    if ((ret = fast_query_event( handle, out )) != STATUS_NOT_IMPLEMENTED)
    {
        if (!ret && ret_len) *ret_len = sizeof(EVENT_BASIC_INFORMATION);
        return ret;
    }

    SERVER_START_REQ( query_event )
    {
        req->handle = wine_server_obj_handle( handle );
        if (!(ret = wine_server_call( req )))
        {
            out->EventType  = reply->manual_reset ? NotificationEvent : SynchronizationEvent;
            out->EventState = reply->state;
            if (ret_len) *ret_len = sizeof(EVENT_BASIC_INFORMATION);
        }
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtCreateMutant (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateMutant( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                BOOLEAN owned )
{
    NTSTATUS ret;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE( "access %#x, name %s, owned %u\n", access,
           attr ? debugstr_us(attr->ObjectName) : "(null)", owned );

    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_mutex )
    {
        req->access  = access;
        req->owned   = owned;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return ret;
}


/**************************************************************************
 *              NtOpenMutant (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenMutant( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS ret;

    TRACE( "access %#x, name %s\n", access, attr ? debugstr_us(attr->ObjectName) : "(null)" );

    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_mutex )
    {
        req->access  = access;
        req->attributes = attr->Attributes;
        req->rootdir = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *              NtReleaseMutant (NTDLL.@)
 */
NTSTATUS WINAPI NtReleaseMutant( HANDLE handle, LONG *prev_count )
{
    NTSTATUS ret;

    TRACE( "handle %p, prev_count %p\n", handle, prev_count );

    if ((ret = fast_release_mutex( handle, prev_count )) != STATUS_NOT_IMPLEMENTED)
        return ret;

    SERVER_START_REQ( release_mutex )
    {
        req->handle = wine_server_obj_handle( handle );
        ret = wine_server_call( req );
        if (prev_count) *prev_count = 1 - reply->prev_count;
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************
 *              NtQueryMutant (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryMutant( HANDLE handle, MUTANT_INFORMATION_CLASS class,
                               void *info, ULONG len, ULONG *ret_len )
{
    NTSTATUS ret;
    MUTANT_BASIC_INFORMATION *out = info;

    TRACE("(%p, %u, %p, %u, %p)\n", handle, class, info, len, ret_len);

    if (class != MutantBasicInformation)
    {
        FIXME( "(%p, %d, %d) Unknown class\n", handle, class, len );
        return STATUS_INVALID_INFO_CLASS;
    }

    if (len != sizeof(MUTANT_BASIC_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;

    if ((ret = fast_query_mutex( handle, out )) != STATUS_NOT_IMPLEMENTED)
    {
        if (!ret && ret_len) *ret_len = sizeof(MUTANT_BASIC_INFORMATION);
        return ret;
    }

    SERVER_START_REQ( query_mutex )
    {
        req->handle = wine_server_obj_handle( handle );
        if (!(ret = wine_server_call( req )))
        {
            out->CurrentCount   = 1 - reply->count;
            out->OwnedByCaller  = reply->owned;
            out->AbandonedState = reply->abandoned;
            if (ret_len) *ret_len = sizeof(MUTANT_BASIC_INFORMATION);
        }
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *		NtCreateJobObject (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateJobObject( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS ret;
    data_size_t len;
    struct object_attributes *objattr;

    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_job )
    {
        req->access = access;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    free( objattr );
    return ret;
}


/**************************************************************************
 *		NtOpenJobObject (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenJobObject( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS ret;

    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_job )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *		NtTerminateJobObject (NTDLL.@)
 */
NTSTATUS WINAPI NtTerminateJobObject( HANDLE handle, NTSTATUS status )
{
    NTSTATUS ret;

    TRACE( "(%p, %d)\n", handle, status );

    SERVER_START_REQ( terminate_job )
    {
        req->handle = wine_server_obj_handle( handle );
        req->status = status;
        ret = wine_server_call( req );
    }
    SERVER_END_REQ;

    return ret;
}


/**************************************************************************
 *		NtQueryInformationJobObject (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryInformationJobObject( HANDLE handle, JOBOBJECTINFOCLASS class, void *info,
                                             ULONG len, ULONG *ret_len )
{
    NTSTATUS ret;

    TRACE( "semi-stub: %p %u %p %u %p\n", handle, class, info, len, ret_len );

    if (class >= MaxJobObjectInfoClass) return STATUS_INVALID_PARAMETER;

    switch (class)
    {
    case JobObjectBasicAccountingInformation:
    {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION *accounting = info;

        if (len < sizeof(*accounting)) return STATUS_INFO_LENGTH_MISMATCH;
        SERVER_START_REQ(get_job_info)
        {
            req->handle = wine_server_obj_handle( handle );
            if (!(ret = wine_server_call( req )))
            {
                memset( accounting, 0, sizeof(*accounting) );
                accounting->TotalProcesses = reply->total_processes;
                accounting->ActiveProcesses = reply->active_processes;
            }
        }
        SERVER_END_REQ;
        if (ret_len) *ret_len = sizeof(*accounting);
        return ret;
    }
    case JobObjectBasicProcessIdList:
    {
        JOBOBJECT_BASIC_PROCESS_ID_LIST *process = info;

        if (len < sizeof(*process)) return STATUS_INFO_LENGTH_MISMATCH;
        memset( process, 0, sizeof(*process) );
        if (ret_len) *ret_len = sizeof(*process);
        return STATUS_SUCCESS;
    }
    case JobObjectExtendedLimitInformation:
    {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION *extended_limit = info;

        if (len < sizeof(*extended_limit)) return STATUS_INFO_LENGTH_MISMATCH;
        memset( extended_limit, 0, sizeof(*extended_limit) );
        if (ret_len) *ret_len = sizeof(*extended_limit);
        return STATUS_SUCCESS;
    }
    case JobObjectBasicLimitInformation:
    {
        JOBOBJECT_BASIC_LIMIT_INFORMATION *basic_limit = info;

        if (len < sizeof(*basic_limit)) return STATUS_INFO_LENGTH_MISMATCH;
        memset( basic_limit, 0, sizeof(*basic_limit) );
        if (ret_len) *ret_len = sizeof(*basic_limit);
        return STATUS_SUCCESS;
    }
    default:
        return STATUS_NOT_IMPLEMENTED;
    }
}


/**************************************************************************
 *		NtSetInformationJobObject (NTDLL.@)
 */
NTSTATUS WINAPI NtSetInformationJobObject( HANDLE handle, JOBOBJECTINFOCLASS class, void *info, ULONG len )
{
    NTSTATUS status = STATUS_NOT_IMPLEMENTED;
    JOBOBJECT_BASIC_LIMIT_INFORMATION *basic_limit;
    ULONG info_size = sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION);
    DWORD limit_flags = JOB_OBJECT_BASIC_LIMIT_VALID_FLAGS;

    TRACE( "(%p, %u, %p, %u)\n", handle, class, info, len );

    if (class >= MaxJobObjectInfoClass) return STATUS_INVALID_PARAMETER;

    switch (class)
    {

    case JobObjectExtendedLimitInformation:
        info_size = sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION);
        limit_flags = JOB_OBJECT_EXTENDED_LIMIT_VALID_FLAGS;
        /* fall through */
    case JobObjectBasicLimitInformation:
        if (len != info_size) return STATUS_INVALID_PARAMETER;
        basic_limit = info;
        if (basic_limit->LimitFlags & ~limit_flags) return STATUS_INVALID_PARAMETER;
        SERVER_START_REQ( set_job_limits )
        {
            req->handle = wine_server_obj_handle( handle );
            req->limit_flags = basic_limit->LimitFlags;
            status = wine_server_call( req );
        }
        SERVER_END_REQ;
        break;
    case JobObjectAssociateCompletionPortInformation:
        if (len != sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT)) return STATUS_INVALID_PARAMETER;
        SERVER_START_REQ( set_job_completion_port )
        {
            JOBOBJECT_ASSOCIATE_COMPLETION_PORT *port_info = info;
            req->job = wine_server_obj_handle( handle );
            req->port = wine_server_obj_handle( port_info->CompletionPort );
            req->key = wine_server_client_ptr( port_info->CompletionKey );
            status = wine_server_call( req );
        }
        SERVER_END_REQ;
        break;
    case JobObjectBasicUIRestrictions:
        status = STATUS_SUCCESS;
        /* fall through */
    default:
        FIXME( "stub: %p %u %p %u\n", handle, class, info, len );
    }
    return status;
}


/**************************************************************************
 *		NtIsProcessInJob (NTDLL.@)
 */
NTSTATUS WINAPI NtIsProcessInJob( HANDLE process, HANDLE job )
{
    NTSTATUS status;

    TRACE( "(%p %p)\n", job, process );

    SERVER_START_REQ( process_in_job )
    {
        req->job     = wine_server_obj_handle( job );
        req->process = wine_server_obj_handle( process );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}


/**************************************************************************
 *		NtAssignProcessToJobObject (NTDLL.@)
 */
NTSTATUS WINAPI NtAssignProcessToJobObject( HANDLE job, HANDLE process )
{
    NTSTATUS status;

    TRACE( "(%p %p)\n", job, process );

    SERVER_START_REQ( assign_job )
    {
        req->job     = wine_server_obj_handle( job );
        req->process = wine_server_obj_handle( process );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}


/**********************************************************************
 *           NtCreateDebugObject  (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateDebugObject( HANDLE *handle, ACCESS_MASK access,
                                     OBJECT_ATTRIBUTES *attr, ULONG flags )
{
    NTSTATUS ret;
    data_size_t len;
    struct object_attributes *objattr;

    if (flags & ~DEBUG_KILL_ON_CLOSE) return STATUS_INVALID_PARAMETER;

    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_debug_obj )
    {
        req->access = access;
        req->flags  = flags;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    free( objattr );
    return ret;
}


/**********************************************************************
 *           NtSetInformationDebugObject  (NTDLL.@)
 */
NTSTATUS WINAPI NtSetInformationDebugObject( HANDLE handle, DEBUGOBJECTINFOCLASS class,
                                             void *info, ULONG len, ULONG *ret_len )
{
    NTSTATUS ret;
    ULONG flags;

    if (class != DebugObjectKillProcessOnExitInformation) return STATUS_INVALID_PARAMETER;
    if (len != sizeof(ULONG))
    {
        if (ret_len) *ret_len = sizeof(ULONG);
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    flags = *(ULONG *)info;
    if (flags & ~DEBUG_KILL_ON_CLOSE) return STATUS_INVALID_PARAMETER;

    SERVER_START_REQ( set_debug_obj_info )
    {
        req->debug = wine_server_obj_handle( handle );
        req->flags = flags;
        ret = wine_server_call( req );
    }
    SERVER_END_REQ;
    if (!ret && ret_len) *ret_len = 0;
    return ret;
}


/* convert the server event data to an NT state change; helper for NtWaitForDebugEvent */
static NTSTATUS event_data_to_state_change( const debug_event_t *data, DBGUI_WAIT_STATE_CHANGE *state )
{
    int i;

    switch (data->code)
    {
    case DbgIdle:
    case DbgReplyPending:
        return STATUS_PENDING;
    case DbgCreateThreadStateChange:
    {
        DBGUI_CREATE_THREAD *info = &state->StateInfo.CreateThread;
        info->HandleToThread         = wine_server_ptr_handle( data->create_thread.handle );
        info->NewThread.StartAddress = wine_server_get_ptr( data->create_thread.start );
        return STATUS_SUCCESS;
    }
    case DbgCreateProcessStateChange:
    {
        DBGUI_CREATE_PROCESS *info = &state->StateInfo.CreateProcessInfo;
        info->HandleToProcess                       = wine_server_ptr_handle( data->create_process.process );
        info->HandleToThread                        = wine_server_ptr_handle( data->create_process.thread );
        info->NewProcess.FileHandle                 = wine_server_ptr_handle( data->create_process.file );
        info->NewProcess.BaseOfImage                = wine_server_get_ptr( data->create_process.base );
        info->NewProcess.DebugInfoFileOffset        = data->create_process.dbg_offset;
        info->NewProcess.DebugInfoSize              = data->create_process.dbg_size;
        info->NewProcess.InitialThread.StartAddress = wine_server_get_ptr( data->create_process.start );
        return STATUS_SUCCESS;
    }
    case DbgExitThreadStateChange:
        state->StateInfo.ExitThread.ExitStatus = data->exit.exit_code;
        return STATUS_SUCCESS;
    case DbgExitProcessStateChange:
        state->StateInfo.ExitProcess.ExitStatus = data->exit.exit_code;
        return STATUS_SUCCESS;
    case DbgExceptionStateChange:
    case DbgBreakpointStateChange:
    case DbgSingleStepStateChange:
    {
        DBGKM_EXCEPTION *info = &state->StateInfo.Exception;
        info->FirstChance = data->exception.first;
        info->ExceptionRecord.ExceptionCode    = data->exception.exc_code;
        info->ExceptionRecord.ExceptionFlags   = data->exception.flags;
        info->ExceptionRecord.ExceptionRecord  = wine_server_get_ptr( data->exception.record );
        info->ExceptionRecord.ExceptionAddress = wine_server_get_ptr( data->exception.address );
        info->ExceptionRecord.NumberParameters = data->exception.nb_params;
        for (i = 0; i < data->exception.nb_params; i++)
            info->ExceptionRecord.ExceptionInformation[i] = data->exception.params[i];
        return STATUS_SUCCESS;
    }
    case DbgLoadDllStateChange:
    {
        DBGKM_LOAD_DLL *info = &state->StateInfo.LoadDll;
        info->FileHandle          = wine_server_ptr_handle( data->load_dll.handle );
        info->BaseOfDll           = wine_server_get_ptr( data->load_dll.base );
        info->DebugInfoFileOffset = data->load_dll.dbg_offset;
        info->DebugInfoSize       = data->load_dll.dbg_size;
        info->NamePointer         = wine_server_get_ptr( data->load_dll.name );
        return STATUS_SUCCESS;
    }
    case DbgUnloadDllStateChange:
        state->StateInfo.UnloadDll.BaseAddress = wine_server_get_ptr( data->unload_dll.base );
        return STATUS_SUCCESS;
    }
    return STATUS_INTERNAL_ERROR;
}

/**********************************************************************
 *           NtWaitForDebugEvent  (NTDLL.@)
 */
NTSTATUS WINAPI NtWaitForDebugEvent( HANDLE handle, BOOLEAN alertable, LARGE_INTEGER *timeout,
                                     DBGUI_WAIT_STATE_CHANGE *state )
{
    debug_event_t data;
    NTSTATUS ret;
    BOOL wait = TRUE;

    for (;;)
    {
        SERVER_START_REQ( wait_debug_event )
        {
            req->debug = wine_server_obj_handle( handle );
            wine_server_set_reply( req, &data, sizeof(data) );
            ret = wine_server_call( req );
            if (!ret && !(ret = event_data_to_state_change( &data, state )))
            {
                state->NewState = data.code;
                state->AppClientId.UniqueProcess = ULongToHandle( reply->pid );
                state->AppClientId.UniqueThread  = ULongToHandle( reply->tid );
            }
        }
        SERVER_END_REQ;

        if (ret != STATUS_PENDING) return ret;
        if (!wait) return STATUS_TIMEOUT;
        wait = FALSE;
        ret = NtWaitForSingleObject( handle, alertable, timeout );
        if (ret != STATUS_WAIT_0) return ret;
    }
}


/**************************************************************************
 *           NtCreateDirectoryObject   (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateDirectoryObject( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS ret;
    data_size_t len;
    struct object_attributes *objattr;

    if (!handle) return STATUS_ACCESS_VIOLATION;

    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_directory )
    {
        req->access = access;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    free( objattr );
    return ret;
}


/**************************************************************************
 *           NtOpenDirectoryObject   (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenDirectoryObject( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS ret;

    if (!handle) return STATUS_ACCESS_VIOLATION;
    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_directory )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *           NtQueryDirectoryObject   (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryDirectoryObject( HANDLE handle, DIRECTORY_BASIC_INFORMATION *buffer,
                                        ULONG size, BOOLEAN single_entry, BOOLEAN restart,
                                        ULONG *context, ULONG *ret_size )
{
    NTSTATUS ret;

    if (restart) *context = 0;

    if (single_entry)
    {
        if (size <= sizeof(*buffer) + 2 * sizeof(WCHAR)) return STATUS_BUFFER_OVERFLOW;

        SERVER_START_REQ( get_directory_entry )
        {
            req->handle = wine_server_obj_handle( handle );
            req->index = *context;
            wine_server_set_reply( req, buffer + 1, size - sizeof(*buffer) - 2*sizeof(WCHAR) );
            if (!(ret = wine_server_call( req )))
            {
                buffer->ObjectName.Buffer = (WCHAR *)(buffer + 1);
                buffer->ObjectName.Length = reply->name_len;
                buffer->ObjectName.MaximumLength = reply->name_len + sizeof(WCHAR);
                buffer->ObjectTypeName.Buffer = (WCHAR *)(buffer + 1) + reply->name_len/sizeof(WCHAR) + 1;
                buffer->ObjectTypeName.Length = wine_server_reply_size( reply ) - reply->name_len;
                buffer->ObjectTypeName.MaximumLength = buffer->ObjectTypeName.Length + sizeof(WCHAR);
                /* make room for the terminating null */
                memmove( buffer->ObjectTypeName.Buffer, buffer->ObjectTypeName.Buffer - 1,
                         buffer->ObjectTypeName.Length );
                buffer->ObjectName.Buffer[buffer->ObjectName.Length/sizeof(WCHAR)] = 0;
                buffer->ObjectTypeName.Buffer[buffer->ObjectTypeName.Length/sizeof(WCHAR)] = 0;
                (*context)++;
            }
        }
        SERVER_END_REQ;
        if (ret_size)
            *ret_size = buffer->ObjectName.MaximumLength + buffer->ObjectTypeName.MaximumLength + sizeof(*buffer);
    }
    else
    {
        FIXME("multiple entries not implemented\n");
        ret = STATUS_NOT_IMPLEMENTED;
    }
    return ret;
}


/**************************************************************************
 *           NtCreateSymbolicLinkObject   (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateSymbolicLinkObject( HANDLE *handle, ACCESS_MASK access,
                                            OBJECT_ATTRIBUTES *attr, UNICODE_STRING *target )
{
    NTSTATUS ret;
    data_size_t len;
    struct object_attributes *objattr;

    if (!handle || !attr || !target) return STATUS_ACCESS_VIOLATION;
    if (!target->Buffer) return STATUS_INVALID_PARAMETER;

    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_symlink )
    {
        req->access = access;
        wine_server_add_data( req, objattr, len );
        wine_server_add_data( req, target->Buffer, target->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    free( objattr );
    return ret;
}


/**************************************************************************
 *           NtOpenSymbolicLinkObject   (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenSymbolicLinkObject( HANDLE *handle, ACCESS_MASK access,
                                          const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS ret;

    if (!handle) return STATUS_ACCESS_VIOLATION;
    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_symlink )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *           NtQuerySymbolicLinkObject   (NTDLL.@)
 */
NTSTATUS WINAPI NtQuerySymbolicLinkObject( HANDLE handle, UNICODE_STRING *target, ULONG *length )
{
    NTSTATUS ret;

    if (!target) return STATUS_ACCESS_VIOLATION;

    SERVER_START_REQ( query_symlink )
    {
        req->handle = wine_server_obj_handle( handle );
        if (target->MaximumLength >= sizeof(WCHAR))
            wine_server_set_reply( req, target->Buffer, target->MaximumLength - sizeof(WCHAR) );
        if (!(ret = wine_server_call( req )))
        {
            target->Length = wine_server_reply_size(reply);
            target->Buffer[target->Length / sizeof(WCHAR)] = 0;
            if (length) *length = reply->total + sizeof(WCHAR);
        }
        else if (length && ret == STATUS_BUFFER_TOO_SMALL) *length = reply->total + sizeof(WCHAR);
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *		NtMakeTemporaryObject (NTDLL.@)
 */
NTSTATUS WINAPI NtMakeTemporaryObject( HANDLE handle )
{
    NTSTATUS ret;

    TRACE("%p\n", handle);

    SERVER_START_REQ( make_temporary )
    {
        req->handle = wine_server_obj_handle( handle );
        ret = wine_server_call( req );
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *		NtCreateTimer (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateTimer( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                               TIMER_TYPE type )
{
    NTSTATUS ret;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE( "access %#x, name %s, type %u\n", access,
           attr ? debugstr_us(attr->ObjectName) : "(null)", type );

    if (type != NotificationTimer && type != SynchronizationTimer) return STATUS_INVALID_PARAMETER;

    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_timer )
    {
        req->access  = access;
        req->manual  = (type == NotificationTimer);
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return ret;

}


/**************************************************************************
 *		NtOpenTimer (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenTimer( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS ret;

    TRACE( "access %#x, name %s\n", access, attr ? debugstr_us(attr->ObjectName) : "(null)" );

    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_timer )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *		NtSetTimer (NTDLL.@)
 */
NTSTATUS WINAPI NtSetTimer( HANDLE handle, const LARGE_INTEGER *when, PTIMER_APC_ROUTINE callback,
                            void *arg, BOOLEAN resume, ULONG period, BOOLEAN *state )
{
    NTSTATUS ret = STATUS_SUCCESS;

    TRACE( "(%p,%p,%p,%p,%08x,0x%08x,%p)\n", handle, when, callback, arg, resume, period, state );

    SERVER_START_REQ( set_timer )
    {
        req->handle   = wine_server_obj_handle( handle );
        req->period   = period;
        req->expire   = when->QuadPart;
        req->callback = wine_server_client_ptr( callback );
        req->arg      = wine_server_client_ptr( arg );
        ret = wine_server_call( req );
        if (state) *state = reply->signaled;
    }
    SERVER_END_REQ;

    /* set error but can still succeed */
    if (resume && ret == STATUS_SUCCESS) return STATUS_TIMER_RESUME_IGNORED;
    return ret;
}


/**************************************************************************
 *		NtCancelTimer (NTDLL.@)
 */
NTSTATUS WINAPI NtCancelTimer( HANDLE handle, BOOLEAN *state )
{
    NTSTATUS ret;

    TRACE( "handle %p, state %p\n", handle, state );

    SERVER_START_REQ( cancel_timer )
    {
        req->handle = wine_server_obj_handle( handle );
        ret = wine_server_call( req );
        if (state) *state = reply->signaled;
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *		NtQueryTimer (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryTimer( HANDLE handle, TIMER_INFORMATION_CLASS class,
                              void *info, ULONG len, ULONG *ret_len )
{
    TIMER_BASIC_INFORMATION *basic_info = info;
    NTSTATUS ret;
    LARGE_INTEGER now;

    TRACE( "(%p,%d,%p,0x%08x,%p)\n", handle, class, info, len, ret_len );

    switch (class)
    {
    case TimerBasicInformation:
        if (len < sizeof(TIMER_BASIC_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;

        SERVER_START_REQ( get_timer_info )
        {
            req->handle = wine_server_obj_handle( handle );
            ret = wine_server_call(req);
            /* convert server time to absolute NTDLL time */
            basic_info->RemainingTime.QuadPart = reply->when;
            basic_info->TimerState = reply->signaled;
        }
        SERVER_END_REQ;

        /* convert into relative time */
        if (basic_info->RemainingTime.QuadPart > 0) NtQuerySystemTime( &now );
        else
        {
            NtQueryPerformanceCounter( &now, NULL );
            basic_info->RemainingTime.QuadPart = -basic_info->RemainingTime.QuadPart;
        }

        if (now.QuadPart > basic_info->RemainingTime.QuadPart)
            basic_info->RemainingTime.QuadPart = 0;
        else
            basic_info->RemainingTime.QuadPart -= now.QuadPart;

        if (ret_len) *ret_len = sizeof(TIMER_BASIC_INFORMATION);
        return ret;
    }

    FIXME( "Unhandled class %d\n", class );
    return STATUS_INVALID_INFO_CLASS;
}


/******************************************************************
 *		NtWaitForMultipleObjects (NTDLL.@)
 */
NTSTATUS WINAPI NtWaitForMultipleObjects( DWORD count, const HANDLE *handles, BOOLEAN wait_any,
                                          BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    select_op_t select_op;
    UINT i, flags = SELECT_INTERRUPTIBLE;
    NTSTATUS ret;

    if (!count || count > MAXIMUM_WAIT_OBJECTS) return STATUS_INVALID_PARAMETER_1;

    if (TRACE_ON(sync))
    {
        TRACE( "wait_any %u, alertable %u, handles {%p", wait_any, alertable, handles[0] );
        for (i = 1; i < count; i++) TRACE( ", %p", handles[i] );
        TRACE( "}, timeout %s\n", debugstr_timeout(timeout) );
    }

    if ((ret = fast_wait( count, handles, wait_any, alertable, timeout )) != STATUS_NOT_IMPLEMENTED)
    {
        TRACE( "-> %#x\n", ret );
        return ret;
    }

    if (alertable) flags |= SELECT_ALERTABLE;
    select_op.wait.op = wait_any ? SELECT_WAIT : SELECT_WAIT_ALL;
    for (i = 0; i < count; i++) select_op.wait.handles[i] = wine_server_obj_handle( handles[i] );
    ret = server_wait( &select_op, offsetof( select_op_t, wait.handles[count] ), flags, timeout );
    TRACE( "-> %#x\n", ret );
    return ret;
}


/******************************************************************
 *		NtWaitForSingleObject (NTDLL.@)
 */
NTSTATUS WINAPI NtWaitForSingleObject( HANDLE handle, BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    return NtWaitForMultipleObjects( 1, &handle, FALSE, alertable, timeout );
}


/******************************************************************
 *		NtSignalAndWaitForSingleObject (NTDLL.@)
 */
NTSTATUS WINAPI NtSignalAndWaitForSingleObject( HANDLE signal, HANDLE wait,
                                                BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    select_op_t select_op;
    UINT flags = SELECT_INTERRUPTIBLE;
    NTSTATUS ret;

    TRACE( "signal %p, wait %p, alertable %u, timeout %s\n", signal, wait, alertable, debugstr_timeout(timeout) );

    if (!signal) return STATUS_INVALID_HANDLE;

    if ((ret = fast_signal_and_wait( signal, wait, alertable, timeout )) != STATUS_NOT_IMPLEMENTED)
        return ret;

    if (alertable) flags |= SELECT_ALERTABLE;
    select_op.signal_and_wait.op = SELECT_SIGNAL_AND_WAIT;
    select_op.signal_and_wait.wait = wine_server_obj_handle( wait );
    select_op.signal_and_wait.signal = wine_server_obj_handle( signal );
    return server_wait( &select_op, sizeof(select_op.signal_and_wait), flags, timeout );
}


/******************************************************************
 *		NtYieldExecution (NTDLL.@)
 */
NTSTATUS WINAPI NtYieldExecution(void)
{
#ifdef HAVE_SCHED_YIELD
    sched_yield();
    return STATUS_SUCCESS;
#else
    return STATUS_NO_YIELD_PERFORMED;
#endif
}


/******************************************************************
 *		NtDelayExecution (NTDLL.@)
 */
NTSTATUS WINAPI NtDelayExecution( BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
//    TRACE( "alertable %u, timeout %s\n", alertable, debugstr_timeout(timeout) );

    /* if alertable, we need to query the server */
    if (alertable) return server_wait( NULL, 0, SELECT_INTERRUPTIBLE | SELECT_ALERTABLE, timeout );

    if (!timeout || timeout->QuadPart == TIMEOUT_INFINITE)  /* sleep forever */
    {
        for (;;) select( 0, NULL, NULL, NULL, NULL );
    }
    else
    {
        LARGE_INTEGER now;
        timeout_t when, diff;

        if ((when = timeout->QuadPart) < 0)
        {
            NtQuerySystemTime( &now );
            when = now.QuadPart - when;
        }

        /* Note that we yield after establishing the desired timeout */
        NtYieldExecution();
        if (!when) return STATUS_SUCCESS;

        for (;;)
        {
            struct timeval tv;
            NtQuerySystemTime( &now );
            diff = (when - now.QuadPart + 9) / 10;
            if (diff <= 0) break;
            tv.tv_sec  = diff / 1000000;
            tv.tv_usec = diff % 1000000;
            if (select( 0, NULL, NULL, NULL, &tv ) != -1) break;
        }
    }
    return STATUS_SUCCESS;
}


/******************************************************************************
 *              NtQueryPerformanceCounter (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryPerformanceCounter( LARGE_INTEGER *counter, LARGE_INTEGER *frequency )
{
    counter->QuadPart = monotonic_counter();
    if (frequency) frequency->QuadPart = TICKSPERSEC;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              NtQuerySystemTime (NTDLL.@)
 */
NTSTATUS WINAPI NtQuerySystemTime( LARGE_INTEGER *time )
{
#ifdef HAVE_CLOCK_GETTIME
    struct timespec ts;
    static clockid_t clock_id = CLOCK_MONOTONIC; /* placeholder */

    if (clock_id == CLOCK_MONOTONIC)
    {
#ifdef CLOCK_REALTIME_COARSE
        struct timespec res;

        /* Use CLOCK_REALTIME_COARSE if it has 1 ms or better resolution */
        if (!clock_getres( CLOCK_REALTIME_COARSE, &res ) && res.tv_sec == 0 && res.tv_nsec <= 1000000)
            clock_id = CLOCK_REALTIME_COARSE;
        else
#endif /* CLOCK_REALTIME_COARSE */
            clock_id = CLOCK_REALTIME;
    }

    if (!clock_gettime( clock_id, &ts ))
    {
        time->QuadPart = ticks_from_time_t( ts.tv_sec ) + (ts.tv_nsec + 50) / 100;
    }
    else
#endif /* HAVE_CLOCK_GETTIME */
    {
        struct timeval now;

        gettimeofday( &now, 0 );
        time->QuadPart = ticks_from_time_t( now.tv_sec ) + now.tv_usec * 10;
    }
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              NtSetSystemTime (NTDLL.@)
 */
NTSTATUS WINAPI NtSetSystemTime( const LARGE_INTEGER *new, LARGE_INTEGER *old )
{
    LARGE_INTEGER now;
    LONGLONG diff;

    NtQuerySystemTime( &now );
    if (old) *old = now;
    diff = new->QuadPart - now.QuadPart;
    if (diff > -TICKSPERSEC / 2 && diff < TICKSPERSEC / 2) return STATUS_SUCCESS;
    ERR( "not allowed: difference %d ms\n", (int)(diff / 10000) );
    return STATUS_PRIVILEGE_NOT_HELD;
}


/***********************************************************************
 *              NtQueryTimerResolution (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryTimerResolution( ULONG *min_res, ULONG *max_res, ULONG *current_res )
{
    FIXME( "(%p,%p,%p), stub!\n", min_res, max_res, current_res );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *              NtSetTimerResolution (NTDLL.@)
 */
NTSTATUS WINAPI NtSetTimerResolution( ULONG res, BOOLEAN set, ULONG *current_res )
{
    FIXME( "(%u,%u,%p), stub!\n", res, set, current_res );
    return STATUS_NOT_IMPLEMENTED;
}


/******************************************************************************
 *              NtSetIntervalProfile (NTDLL.@)
 */
NTSTATUS WINAPI NtSetIntervalProfile( ULONG interval, KPROFILE_SOURCE source )
{
    FIXME( "%u,%d\n", interval, source );
    return STATUS_SUCCESS;
}


/******************************************************************************
 *              NtGetTickCount (NTDLL.@)
 */
ULONG WINAPI NtGetTickCount(void)
{
    /* note: we ignore TickCountMultiplier */
    return user_shared_data->u.TickCount.LowPart;
}


/******************************************************************************
 *              RtlGetSystemTimePrecise (NTDLL.@)
 */
LONGLONG WINAPI RtlGetSystemTimePrecise(void)
{
    struct timeval now;
#ifdef HAVE_CLOCK_GETTIME
    struct timespec ts;

    if (!clock_gettime( CLOCK_REALTIME, &ts ))
        return ticks_from_time_t( ts.tv_sec ) + (ts.tv_nsec + 50) / 100;
#endif
    gettimeofday( &now, 0 );
    return ticks_from_time_t( now.tv_sec ) + now.tv_usec * 10;
}


/******************************************************************************
 *              NtCreateKeyedEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateKeyedEvent( HANDLE *handle, ACCESS_MASK access,
                                    const OBJECT_ATTRIBUTES *attr, ULONG flags )
{
    NTSTATUS ret;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE( "access %#x, name %s, flags %#x\n", access,
           attr ? debugstr_us(attr->ObjectName) : "(null)", flags );

    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_keyed_event )
    {
        req->access = access;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return ret;
}


/******************************************************************************
 *              NtOpenKeyedEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenKeyedEvent( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS ret;

    TRACE( "access %#x, name %s\n", access, attr ? debugstr_us(attr->ObjectName) : "(null)" );

    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_keyed_event )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}

/******************************************************************************
 *              NtWaitForKeyedEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtWaitForKeyedEvent( HANDLE handle, const void *key,
                                     BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    select_op_t select_op;
    UINT flags = SELECT_INTERRUPTIBLE;

    TRACE( "handle %p, key %p, alertable %u, timeout %s\n", handle, key, alertable, debugstr_timeout(timeout) );

    if (!handle) handle = keyed_event;
    if ((ULONG_PTR)key & 1) return STATUS_INVALID_PARAMETER_1;
    if (alertable) flags |= SELECT_ALERTABLE;
    select_op.keyed_event.op     = SELECT_KEYED_EVENT_WAIT;
    select_op.keyed_event.handle = wine_server_obj_handle( handle );
    select_op.keyed_event.key    = wine_server_client_ptr( key );
    return server_wait( &select_op, sizeof(select_op.keyed_event), flags, timeout );
}


/******************************************************************************
 *              NtReleaseKeyedEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtReleaseKeyedEvent( HANDLE handle, const void *key,
                                     BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    select_op_t select_op;
    UINT flags = SELECT_INTERRUPTIBLE;

    TRACE( "handle %p, key %p, alertable %u, timeout %s\n", handle, key, alertable, debugstr_timeout(timeout) );

    if (!handle) handle = keyed_event;
    if ((ULONG_PTR)key & 1) return STATUS_INVALID_PARAMETER_1;
    if (alertable) flags |= SELECT_ALERTABLE;
    select_op.keyed_event.op     = SELECT_KEYED_EVENT_RELEASE;
    select_op.keyed_event.handle = wine_server_obj_handle( handle );
    select_op.keyed_event.key    = wine_server_client_ptr( key );
    return server_wait( &select_op, sizeof(select_op.keyed_event), flags, timeout );
}


/***********************************************************************
 *             NtCreateIoCompletion (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateIoCompletion( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                      ULONG threads )
{
    NTSTATUS status;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE( "(%p, %x, %p, %d)\n", handle, access, attr, threads );

    if (!handle) return STATUS_INVALID_PARAMETER;
    if ((status = alloc_object_attributes( attr, &objattr, &len ))) return status;

    SERVER_START_REQ( create_completion )
    {
        req->access     = access;
        req->concurrent = threads;
        wine_server_add_data( req, objattr, len );
        if (!(status = wine_server_call( req ))) *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return status;
}


/***********************************************************************
 *             NtOpenIoCompletion (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenIoCompletion( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS status;

    if (!handle) return STATUS_INVALID_PARAMETER;
    if ((status = validate_open_object_attributes( attr ))) return status;

    SERVER_START_REQ( open_completion )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        status = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return status;
}


/***********************************************************************
 *             NtSetIoCompletion (NTDLL.@)
 */
NTSTATUS WINAPI NtSetIoCompletion( HANDLE handle, ULONG_PTR key, ULONG_PTR value,
                                   NTSTATUS status, SIZE_T count )
{
    NTSTATUS ret;

    TRACE( "(%p, %lx, %lx, %x, %lx)\n", handle, key, value, status, count );

    SERVER_START_REQ( add_completion )
    {
        req->handle      = wine_server_obj_handle( handle );
        req->ckey        = key;
        req->cvalue      = value;
        req->status      = status;
        req->information = count;
        ret = wine_server_call( req );
    }
    SERVER_END_REQ;
    return ret;
}


/***********************************************************************
 *             NtRemoveIoCompletion (NTDLL.@)
 */
NTSTATUS WINAPI NtRemoveIoCompletion( HANDLE handle, ULONG_PTR *key, ULONG_PTR *value,
                                      IO_STATUS_BLOCK *io, LARGE_INTEGER *timeout )
{
    NTSTATUS status;

    TRACE( "(%p, %p, %p, %p, %p)\n", handle, key, value, io, timeout );

    for (;;)
    {
        SERVER_START_REQ( remove_completion )
        {
            req->handle = wine_server_obj_handle( handle );
            if (!(status = wine_server_call( req )))
            {
                *key            = reply->ckey;
                *value          = reply->cvalue;
                io->Information = reply->information;
                io->u.Status    = reply->status;
            }
        }
        SERVER_END_REQ;
        if (status != STATUS_PENDING) return status;
        status = NtWaitForSingleObject( handle, FALSE, timeout );
        if (status != WAIT_OBJECT_0) return status;
    }
}


/***********************************************************************
 *             NtRemoveIoCompletionEx (NTDLL.@)
 */
NTSTATUS WINAPI NtRemoveIoCompletionEx( HANDLE handle, FILE_IO_COMPLETION_INFORMATION *info, ULONG count,
                                        ULONG *written, LARGE_INTEGER *timeout, BOOLEAN alertable )
{
    NTSTATUS status;
    ULONG i = 0;

    TRACE( "%p %p %u %p %p %u\n", handle, info, count, written, timeout, alertable );

    for (;;)
    {
        while (i < count)
        {
            SERVER_START_REQ( remove_completion )
            {
                req->handle = wine_server_obj_handle( handle );
                if (!(status = wine_server_call( req )))
                {
                    info[i].CompletionKey             = reply->ckey;
                    info[i].CompletionValue           = reply->cvalue;
                    info[i].IoStatusBlock.Information = reply->information;
                    info[i].IoStatusBlock.u.Status    = reply->status;
                }
            }
            SERVER_END_REQ;
            if (status != STATUS_SUCCESS) break;
            ++i;
        }
        if (i || status != STATUS_PENDING)
        {
            if (status == STATUS_PENDING) status = STATUS_SUCCESS;
            break;
        }
        status = NtWaitForSingleObject( handle, alertable, timeout );
        if (status != WAIT_OBJECT_0) break;
    }
    *written = i ? i : 1;
    return status;
}


/***********************************************************************
 *             NtQueryIoCompletion (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryIoCompletion( HANDLE handle, IO_COMPLETION_INFORMATION_CLASS class,
                                     void *buffer, ULONG len, ULONG *ret_len )
{
    NTSTATUS status;

    TRACE( "(%p, %d, %p, 0x%x, %p)\n", handle, class, buffer, len, ret_len );

    if (!buffer) return STATUS_INVALID_PARAMETER;

    switch (class)
    {
    case IoCompletionBasicInformation:
    {
        ULONG *info = buffer;
        if (ret_len) *ret_len = sizeof(*info);
        if (len == sizeof(*info))
        {
            SERVER_START_REQ( query_completion )
            {
                req->handle = wine_server_obj_handle( handle );
                if (!(status = wine_server_call( req ))) *info = reply->depth;
            }
            SERVER_END_REQ;
        }
        else status = STATUS_INFO_LENGTH_MISMATCH;
        break;
    }
    default:
        return STATUS_INVALID_PARAMETER;
    }
    return status;
}


/***********************************************************************
 *             NtCreateSection (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateSection( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                 const LARGE_INTEGER *size, ULONG protect,
                                 ULONG sec_flags, HANDLE file )
{
    NTSTATUS ret;
    unsigned int file_access;
    data_size_t len;
    struct object_attributes *objattr;

    switch (protect & 0xff)
    {
    case PAGE_READONLY:
    case PAGE_EXECUTE_READ:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_WRITECOPY:
        file_access = FILE_READ_DATA;
        break;
    case PAGE_READWRITE:
    case PAGE_EXECUTE_READWRITE:
        if (sec_flags & SEC_IMAGE) file_access = FILE_READ_DATA;
        else file_access = FILE_READ_DATA | FILE_WRITE_DATA;
        break;
    case PAGE_EXECUTE:
    case PAGE_NOACCESS:
        file_access = 0;
        break;
    default:
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_mapping )
    {
        req->access      = access;
        req->flags       = sec_flags;
        req->file_handle = wine_server_obj_handle( file );
        req->file_access = file_access;
        req->size        = size ? size->QuadPart : 0;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return ret;
}


/***********************************************************************
 *             NtOpenSection (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenSection( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS ret;

    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_mapping )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/***********************************************************************
 *             NtCreatePort (NTDLL.@)
 */
NTSTATUS WINAPI NtCreatePort( HANDLE *handle, OBJECT_ATTRIBUTES *attr, ULONG info_len,
                              ULONG data_len, ULONG *reserved )
{
    FIXME( "(%p,%p,%u,%u,%p),stub!\n", handle, attr, info_len, data_len, reserved );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtConnectPort (NTDLL.@)
 */
NTSTATUS WINAPI NtConnectPort( HANDLE *handle, UNICODE_STRING *name, SECURITY_QUALITY_OF_SERVICE *qos,
                               LPC_SECTION_WRITE *write, LPC_SECTION_READ *read, ULONG *max_len,
                               void *info, ULONG *info_len )
{
    FIXME( "(%p,%s,%p,%p,%p,%p,%p,%p),stub!\n", handle, debugstr_us(name), qos,
           write, read, max_len, info, info_len );
    if (info && info_len) TRACE("msg = %s\n", debugstr_an( info, *info_len ));
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtSecureConnectPort (NTDLL.@)
 */
NTSTATUS WINAPI NtSecureConnectPort( HANDLE *handle, UNICODE_STRING *name, SECURITY_QUALITY_OF_SERVICE *qos,
                                     LPC_SECTION_WRITE *write, PSID sid, LPC_SECTION_READ *read,
                                     ULONG *max_len, void *info, ULONG *info_len )
{
    FIXME( "(%p,%s,%p,%p,%p,%p,%p,%p,%p),stub!\n", handle, debugstr_us(name), qos,
           write, sid, read, max_len, info, info_len );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtListenPort (NTDLL.@)
 */
NTSTATUS WINAPI NtListenPort( HANDLE handle, LPC_MESSAGE *msg )
{
    FIXME("(%p,%p),stub!\n", handle, msg );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtAcceptConnectPort (NTDLL.@)
 */
NTSTATUS WINAPI NtAcceptConnectPort( HANDLE *handle, ULONG id, LPC_MESSAGE *msg, BOOLEAN accept,
                                     LPC_SECTION_WRITE *write, LPC_SECTION_READ *read )
{
    FIXME("(%p,%u,%p,%d,%p,%p),stub!\n", handle, id, msg, accept, write, read );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtCompleteConnectPort (NTDLL.@)
 */
NTSTATUS WINAPI NtCompleteConnectPort( HANDLE handle )
{
    FIXME( "(%p),stub!\n", handle );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtRegisterThreadTerminatePort (NTDLL.@)
 */
NTSTATUS WINAPI NtRegisterThreadTerminatePort( HANDLE handle )
{
    FIXME( "(%p),stub!\n", handle );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtRequestWaitReplyPort (NTDLL.@)
 */
NTSTATUS WINAPI NtRequestWaitReplyPort( HANDLE handle, LPC_MESSAGE *msg_in, LPC_MESSAGE *msg_out )
{
    FIXME( "(%p,%p,%p),stub!\n", handle, msg_in, msg_out );
    if (msg_in)
        TRACE("datasize %u msgsize %u type %u ranges %u client %p/%p msgid %lu size %lu data %s\n",
              msg_in->DataSize, msg_in->MessageSize, msg_in->MessageType, msg_in->VirtualRangesOffset,
              msg_in->ClientId.UniqueProcess, msg_in->ClientId.UniqueThread, msg_in->MessageId,
              msg_in->SectionSize, debugstr_an( (const char *)msg_in->Data, msg_in->DataSize ));
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtReplyWaitReceivePort (NTDLL.@)
 */
NTSTATUS WINAPI NtReplyWaitReceivePort( HANDLE handle, ULONG *id, LPC_MESSAGE *reply, LPC_MESSAGE *msg )
{
    FIXME("(%p,%p,%p,%p),stub!\n", handle, id, reply, msg );
    return STATUS_NOT_IMPLEMENTED;
}


#define MAX_ATOM_LEN  255
#define IS_INTATOM(x) (((ULONG_PTR)(x) >> 16) == 0)

static NTSTATUS is_integral_atom( const WCHAR *atomstr, ULONG len, RTL_ATOM *ret_atom )
{
    RTL_ATOM atom;

    if ((ULONG_PTR)atomstr >> 16)
    {
        const WCHAR* ptr = atomstr;
        if (!len) return STATUS_OBJECT_NAME_INVALID;

        if (*ptr++ == '#')
        {
            atom = 0;
            while (ptr < atomstr + len && *ptr >= '0' && *ptr <= '9')
            {
                atom = atom * 10 + *ptr++ - '0';
            }
            if (ptr > atomstr + 1 && ptr == atomstr + len) goto done;
        }
        if (len > MAX_ATOM_LEN) return STATUS_INVALID_PARAMETER;
        return STATUS_MORE_ENTRIES;
    }
    else atom = LOWORD( atomstr );
done:
    if (!atom || atom >= MAXINTATOM) return STATUS_INVALID_PARAMETER;
    *ret_atom = atom;
    return STATUS_SUCCESS;
}

static ULONG integral_atom_name( WCHAR *buffer, ULONG len, RTL_ATOM atom )
{
    char tmp[16];
    int ret = sprintf( tmp, "#%u", atom );

    len /= sizeof(WCHAR);
    if (len)
    {
        if (len <= ret) ret = len - 1;
        ascii_to_unicode( buffer, tmp, ret );
        buffer[ret] = 0;
    }
    return ret * sizeof(WCHAR);
}


/***********************************************************************
 *             NtAddAtom (NTDLL.@)
 */
NTSTATUS WINAPI NtAddAtom( const WCHAR *name, ULONG length, RTL_ATOM *atom )
{
    NTSTATUS status = is_integral_atom( name, length / sizeof(WCHAR), atom );

    if (status == STATUS_MORE_ENTRIES)
    {
        SERVER_START_REQ( add_atom )
        {
            wine_server_add_data( req, name, length );
            status = wine_server_call( req );
            *atom = reply->atom;
        }
        SERVER_END_REQ;
    }
    TRACE( "%s -> %x\n", debugstr_wn(name, length/sizeof(WCHAR)), status == STATUS_SUCCESS ? *atom : 0 );
    return status;
}


/***********************************************************************
 *             NtDeleteAtom (NTDLL.@)
 */
NTSTATUS WINAPI NtDeleteAtom( RTL_ATOM atom )
{
    NTSTATUS status;

    SERVER_START_REQ( delete_atom )
    {
        req->atom = atom;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}


/***********************************************************************
 *             NtFindAtom (NTDLL.@)
 */
NTSTATUS WINAPI NtFindAtom( const WCHAR *name, ULONG length, RTL_ATOM *atom )
{
    NTSTATUS status = is_integral_atom( name, length / sizeof(WCHAR), atom );

    if (status == STATUS_MORE_ENTRIES)
    {
        SERVER_START_REQ( find_atom )
        {
            wine_server_add_data( req, name, length );
            status = wine_server_call( req );
            *atom = reply->atom;
        }
        SERVER_END_REQ;
    }
    TRACE( "%s -> %x\n", debugstr_wn(name, length/sizeof(WCHAR)), status == STATUS_SUCCESS ? *atom : 0 );
    return status;
}


/***********************************************************************
 *             NtQueryInformationAtom (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryInformationAtom( RTL_ATOM atom, ATOM_INFORMATION_CLASS class,
                                        void *ptr, ULONG size, ULONG *retsize )
{
    NTSTATUS status;

    switch (class)
    {
    case AtomBasicInformation:
    {
        ULONG name_len;
        ATOM_BASIC_INFORMATION *abi = ptr;

        if (size < sizeof(ATOM_BASIC_INFORMATION)) return STATUS_INVALID_PARAMETER;
        name_len = size - sizeof(ATOM_BASIC_INFORMATION);

        if (atom < MAXINTATOM)
        {
            if (atom)
            {
                abi->NameLength = integral_atom_name( abi->Name, name_len, atom );
                status = name_len ? STATUS_SUCCESS : STATUS_BUFFER_TOO_SMALL;
                abi->ReferenceCount = 1;
                abi->Pinned = 1;
            }
            else status = STATUS_INVALID_PARAMETER;
        }
        else
        {
            SERVER_START_REQ( get_atom_information )
            {
                req->atom = atom;
                if (name_len) wine_server_set_reply( req, abi->Name, name_len );
                status = wine_server_call( req );
                if (status == STATUS_SUCCESS)
                {
                    name_len = wine_server_reply_size( reply );
                    if (name_len)
                    {
                        abi->NameLength = name_len;
                        abi->Name[name_len / sizeof(WCHAR)] = 0;
                    }
                    else
                    {
                        name_len = reply->total;
                        abi->NameLength = name_len;
                        status = STATUS_BUFFER_TOO_SMALL;
                    }
                    abi->ReferenceCount = reply->count;
                    abi->Pinned = reply->pinned;
                }
                else name_len = 0;
            }
            SERVER_END_REQ;
        }
        TRACE( "%x -> %s (%u)\n", atom, debugstr_wn(abi->Name, abi->NameLength / sizeof(WCHAR)), status );
        if (retsize) *retsize = sizeof(ATOM_BASIC_INFORMATION) + name_len;
        break;
    }

    default:
        FIXME( "Unsupported class %u\n", class );
        status = STATUS_INVALID_INFO_CLASS;
        break;
    }
    return status;
}


#ifdef __linux__

NTSTATUS CDECL fast_RtlpWaitForCriticalSection( RTL_CRITICAL_SECTION *crit, int timeout )
{
    int val;
    struct timespec timespec;

    if (!use_futexes()) return STATUS_NOT_IMPLEMENTED;

    timespec.tv_sec  = timeout;
    timespec.tv_nsec = 0;
    while ((val = InterlockedCompareExchange( (int *)&crit->LockSemaphore, 0, 1 )) != 1)
    {
        /* note: this may wait longer than specified in case of signals or */
        /*       multiple wake-ups, but that shouldn't be a problem */
        if (futex_wait( (int *)&crit->LockSemaphore, val, &timespec ) == -1 && errno == ETIMEDOUT)
            return STATUS_TIMEOUT;
    }
    return STATUS_WAIT_0;
}

NTSTATUS CDECL fast_RtlpUnWaitCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    if (!use_futexes()) return STATUS_NOT_IMPLEMENTED;

    *(int *)&crit->LockSemaphore = 1;
    futex_wake( (int *)&crit->LockSemaphore, 1 );
    return STATUS_SUCCESS;
}

NTSTATUS CDECL fast_RtlDeleteCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    if (!use_futexes()) return STATUS_NOT_IMPLEMENTED;
    return STATUS_SUCCESS;
}

#elif defined(__APPLE__)

static inline semaphore_t get_mach_semaphore( RTL_CRITICAL_SECTION *crit )
{
    semaphore_t ret = *(int *)&crit->LockSemaphore;
    if (!ret)
    {
        semaphore_t sem;
        if (semaphore_create( mach_task_self(), &sem, SYNC_POLICY_FIFO, 0 )) return 0;
        if (!(ret = InterlockedCompareExchange( (int *)&crit->LockSemaphore, sem, 0 )))
            ret = sem;
        else
            semaphore_destroy( mach_task_self(), sem );  /* somebody beat us to it */
    }
    return ret;
}

NTSTATUS CDECL fast_RtlpWaitForCriticalSection( RTL_CRITICAL_SECTION *crit, int timeout )
{
    mach_timespec_t timespec;
    semaphore_t sem = get_mach_semaphore( crit );

    timespec.tv_sec = timeout;
    timespec.tv_nsec = 0;
    for (;;)
    {
        switch( semaphore_timedwait( sem, timespec ))
        {
        case KERN_SUCCESS:
            return STATUS_WAIT_0;
        case KERN_ABORTED:
            continue;  /* got a signal, restart */
        case KERN_OPERATION_TIMED_OUT:
            return STATUS_TIMEOUT;
        default:
            return STATUS_INVALID_HANDLE;
        }
    }
}

NTSTATUS CDECL fast_RtlpUnWaitCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    semaphore_t sem = get_mach_semaphore( crit );
    semaphore_signal( sem );
    return STATUS_SUCCESS;
}

NTSTATUS CDECL fast_RtlDeleteCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    semaphore_destroy( mach_task_self(), *(int *)&crit->LockSemaphore );
    return STATUS_SUCCESS;
}

#else  /* __APPLE__ */

NTSTATUS CDECL fast_RtlpWaitForCriticalSection( RTL_CRITICAL_SECTION *crit, int timeout )
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS CDECL fast_RtlpUnWaitCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS CDECL fast_RtlDeleteCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    return STATUS_NOT_IMPLEMENTED;
}

#endif


#ifdef __linux__

/* Futex-based SRW lock implementation:
 *
 * Since we can rely on the kernel to release all threads and don't need to
 * worry about NtReleaseKeyedEvent(), we can simplify the layout a bit. The
 * layout looks like this:
 *
 *    31 - Exclusive lock bit, set if the resource is owned exclusively.
 * 30-16 - Number of exclusive waiters. Unlike the fallback implementation,
 *         this does not include the thread owning the lock, or shared threads
 *         waiting on the lock.
 *    15 - Does this lock have any shared waiters? We use this as an
 *         optimization to avoid unnecessary FUTEX_WAKE_BITSET calls when
 *         releasing an exclusive lock.
 *  14-0 - Number of shared owners. Unlike the fallback implementation, this
 *         does not include the number of shared threads waiting on the lock.
 *         Thus the state [1, x, >=1] will never occur.
 */

#define SRWLOCK_FUTEX_EXCLUSIVE_LOCK_BIT        0x80000000
#define SRWLOCK_FUTEX_EXCLUSIVE_WAITERS_MASK    0x7fff0000
#define SRWLOCK_FUTEX_EXCLUSIVE_WAITERS_INC     0x00010000
#define SRWLOCK_FUTEX_SHARED_WAITERS_BIT        0x00008000
#define SRWLOCK_FUTEX_SHARED_OWNERS_MASK        0x00007fff
#define SRWLOCK_FUTEX_SHARED_OWNERS_INC         0x00000001

/* Futex bitmasks; these are independent from the bits in the lock itself. */
#define SRWLOCK_FUTEX_BITSET_EXCLUSIVE  1
#define SRWLOCK_FUTEX_BITSET_SHARED     2

NTSTATUS CDECL fast_RtlTryAcquireSRWLockExclusive( RTL_SRWLOCK *lock )
{
    int old, new, *futex;
    NTSTATUS ret;

    if (!use_futexes()) return STATUS_NOT_IMPLEMENTED;

    if (!(futex = get_futex( &lock->Ptr )))
        return STATUS_NOT_IMPLEMENTED;

    do
    {
        old = *futex;

        if (!(old & SRWLOCK_FUTEX_EXCLUSIVE_LOCK_BIT)
                && !(old & SRWLOCK_FUTEX_SHARED_OWNERS_MASK))
        {
            /* Not locked exclusive or shared. We can try to grab it. */
            new = old | SRWLOCK_FUTEX_EXCLUSIVE_LOCK_BIT;
            ret = STATUS_SUCCESS;
        }
        else
        {
            new = old;
            ret = STATUS_TIMEOUT;
        }
    } while (InterlockedCompareExchange( futex, new, old ) != old);

    return ret;
}

NTSTATUS CDECL fast_RtlAcquireSRWLockExclusive( RTL_SRWLOCK *lock )
{
    int old, new, *futex;
    BOOLEAN wait;

    if (!use_futexes()) return STATUS_NOT_IMPLEMENTED;

    if (!(futex = get_futex( &lock->Ptr )))
        return STATUS_NOT_IMPLEMENTED;

    /* Atomically increment the exclusive waiter count. */
    do
    {
        old = *futex;
        new = old + SRWLOCK_FUTEX_EXCLUSIVE_WAITERS_INC;
        assert(new & SRWLOCK_FUTEX_EXCLUSIVE_WAITERS_MASK);
    } while (InterlockedCompareExchange( futex, new, old ) != old);

    for (;;)
    {
        do
        {
            old = *futex;

            if (!(old & SRWLOCK_FUTEX_EXCLUSIVE_LOCK_BIT)
                    && !(old & SRWLOCK_FUTEX_SHARED_OWNERS_MASK))
            {
                /* Not locked exclusive or shared. We can try to grab it. */
                new = old | SRWLOCK_FUTEX_EXCLUSIVE_LOCK_BIT;
                assert(old & SRWLOCK_FUTEX_EXCLUSIVE_WAITERS_MASK);
                new -= SRWLOCK_FUTEX_EXCLUSIVE_WAITERS_INC;
                wait = FALSE;
            }
            else
            {
                new = old;
                wait = TRUE;
            }
        } while (InterlockedCompareExchange( futex, new, old ) != old);

        if (!wait)
            return STATUS_SUCCESS;

        futex_wait_bitset( futex, new, NULL, SRWLOCK_FUTEX_BITSET_EXCLUSIVE );
    }

    return STATUS_SUCCESS;
}

NTSTATUS CDECL fast_RtlTryAcquireSRWLockShared( RTL_SRWLOCK *lock )
{
    int new, old, *futex;
    NTSTATUS ret;

    if (!use_futexes()) return STATUS_NOT_IMPLEMENTED;

    if (!(futex = get_futex( &lock->Ptr )))
        return STATUS_NOT_IMPLEMENTED;

    do
    {
        old = *futex;

        if (!(old & SRWLOCK_FUTEX_EXCLUSIVE_LOCK_BIT)
                && !(old & SRWLOCK_FUTEX_EXCLUSIVE_WAITERS_MASK))
        {
            /* Not locked exclusive, and no exclusive waiters. We can try to
             * grab it. */
            new = old + SRWLOCK_FUTEX_SHARED_OWNERS_INC;
            assert(new & SRWLOCK_FUTEX_SHARED_OWNERS_MASK);
            ret = STATUS_SUCCESS;
        }
        else
        {
            new = old;
            ret = STATUS_TIMEOUT;
        }
    } while (InterlockedCompareExchange( futex, new, old ) != old);

    return ret;
}

NTSTATUS CDECL fast_RtlAcquireSRWLockShared( RTL_SRWLOCK *lock )
{
    int old, new, *futex;
    BOOLEAN wait;

    if (!use_futexes()) return STATUS_NOT_IMPLEMENTED;

    if (!(futex = get_futex( &lock->Ptr )))
        return STATUS_NOT_IMPLEMENTED;

    for (;;)
    {
        do
        {
            old = *futex;

            if (!(old & SRWLOCK_FUTEX_EXCLUSIVE_LOCK_BIT)
                    && !(old & SRWLOCK_FUTEX_EXCLUSIVE_WAITERS_MASK))
            {
                /* Not locked exclusive, and no exclusive waiters. We can try
                 * to grab it. */
                new = old + SRWLOCK_FUTEX_SHARED_OWNERS_INC;
                assert(new & SRWLOCK_FUTEX_SHARED_OWNERS_MASK);
                wait = FALSE;
            }
            else
            {
                new = old | SRWLOCK_FUTEX_SHARED_WAITERS_BIT;
                wait = TRUE;
            }
        } while (InterlockedCompareExchange( futex, new, old ) != old);

        if (!wait)
            return STATUS_SUCCESS;

        futex_wait_bitset( futex, new, NULL, SRWLOCK_FUTEX_BITSET_SHARED );
    }

    return STATUS_SUCCESS;
}

NTSTATUS CDECL fast_RtlReleaseSRWLockExclusive( RTL_SRWLOCK *lock )
{
    int old, new, *futex;

    if (!use_futexes()) return STATUS_NOT_IMPLEMENTED;

    if (!(futex = get_futex( &lock->Ptr )))
        return STATUS_NOT_IMPLEMENTED;

    do
    {
        old = *futex;

        if (!(old & SRWLOCK_FUTEX_EXCLUSIVE_LOCK_BIT))
        {
            ERR("Lock %p is not owned exclusive! (%#x)\n", lock, *futex);
            return STATUS_RESOURCE_NOT_OWNED;
        }

        new = old & ~SRWLOCK_FUTEX_EXCLUSIVE_LOCK_BIT;

        if (!(new & SRWLOCK_FUTEX_EXCLUSIVE_WAITERS_MASK))
            new &= ~SRWLOCK_FUTEX_SHARED_WAITERS_BIT;
    } while (InterlockedCompareExchange( futex, new, old ) != old);

    if (new & SRWLOCK_FUTEX_EXCLUSIVE_WAITERS_MASK)
        futex_wake_bitset( futex, 1, SRWLOCK_FUTEX_BITSET_EXCLUSIVE );
    else if (old & SRWLOCK_FUTEX_SHARED_WAITERS_BIT)
        futex_wake_bitset( futex, INT_MAX, SRWLOCK_FUTEX_BITSET_SHARED );

    return STATUS_SUCCESS;
}

NTSTATUS CDECL fast_RtlReleaseSRWLockShared( RTL_SRWLOCK *lock )
{
    int old, new, *futex;

    if (!use_futexes()) return STATUS_NOT_IMPLEMENTED;

    if (!(futex = get_futex( &lock->Ptr )))
        return STATUS_NOT_IMPLEMENTED;

    do
    {
        old = *futex;

        if (old & SRWLOCK_FUTEX_EXCLUSIVE_LOCK_BIT)
        {
            ERR("Lock %p is owned exclusive! (%#x)\n", lock, *futex);
            return STATUS_RESOURCE_NOT_OWNED;
        }
        else if (!(old & SRWLOCK_FUTEX_SHARED_OWNERS_MASK))
        {
            ERR("Lock %p is not owned shared! (%#x)\n", lock, *futex);
            return STATUS_RESOURCE_NOT_OWNED;
        }

        new = old - SRWLOCK_FUTEX_SHARED_OWNERS_INC;
    } while (InterlockedCompareExchange( futex, new, old ) != old);

    /* Optimization: only bother waking if there are actually exclusive waiters. */
    if (!(new & SRWLOCK_FUTEX_SHARED_OWNERS_MASK) && (new & SRWLOCK_FUTEX_EXCLUSIVE_WAITERS_MASK))
        futex_wake_bitset( futex, 1, SRWLOCK_FUTEX_BITSET_EXCLUSIVE );

    return STATUS_SUCCESS;
}

NTSTATUS CDECL fast_wait_cv( RTL_CONDITION_VARIABLE *variable, const void *value, const LARGE_INTEGER *timeout )
{
    const char *value_ptr;
    int aligned_value, *futex;
    struct timespec timespec;
    int ret;

    if (!use_futexes())
        return STATUS_NOT_IMPLEMENTED;

    if (!(futex = get_futex( &variable->Ptr )))
        return STATUS_NOT_IMPLEMENTED;

    value_ptr = (const char *)&value;
    value_ptr += ((ULONG_PTR)futex) - ((ULONG_PTR)&variable->Ptr);
    aligned_value = *(int *)value_ptr;

    if (timeout && timeout->QuadPart != TIMEOUT_INFINITE)
    {
        timespec_from_timeout( &timespec, timeout );
        ret = futex_wait( futex, aligned_value, &timespec );
    }
    else
        ret = futex_wait( futex, aligned_value, NULL );

    if (ret == -1 && errno == ETIMEDOUT)
        return STATUS_TIMEOUT;
    return STATUS_WAIT_0;
}

NTSTATUS CDECL fast_RtlWakeConditionVariable( RTL_CONDITION_VARIABLE *variable, int count )
{
    int *futex;

    if (!use_futexes()) return STATUS_NOT_IMPLEMENTED;

    if (!(futex = get_futex( &variable->Ptr )))
        return STATUS_NOT_IMPLEMENTED;

    InterlockedIncrement( futex );
    futex_wake( futex, count );
    return STATUS_SUCCESS;
}


/* We can't map addresses to futex directly, because an application can wait on
 * 8 bytes, and we can't pass all 8 as the compare value to futex(). Instead we
 * map all addresses to a small fixed table of futexes. This may result in
 * spurious wakes, but the application is already expected to handle those. */

static int addr_futex_table[256];

static inline int *hash_addr( const void *addr )
{
    ULONG_PTR val = (ULONG_PTR)addr;

    return &addr_futex_table[(val >> 2) & 255];
}

static inline NTSTATUS fast_wait_addr( const void *addr, const void *cmp, SIZE_T size,
                                       const LARGE_INTEGER *timeout )
{
    int *futex;
    int val;
    struct timespec timespec;
    int ret;

    if (!use_futexes())
        return STATUS_NOT_IMPLEMENTED;

    futex = hash_addr( addr );

    /* We must read the previous value of the futex before checking the value
     * of the address being waited on. That way, if we receive a wake between
     * now and waiting on the futex, we know that val will have changed.
     * Use an atomic load so that memory accesses are ordered between this read
     * and the increment below. */
    val = InterlockedCompareExchange( futex, 0, 0 );
    if (!compare_addr( addr, cmp, size ))
        return STATUS_SUCCESS;

    if (timeout)
    {
        timespec_from_timeout( &timespec, timeout );
        ret = futex_wait( futex, val, &timespec );
    }
    else
        ret = futex_wait( futex, val, NULL );

    if (ret == -1 && errno == ETIMEDOUT)
        return STATUS_TIMEOUT;
    return STATUS_SUCCESS;
}

static inline NTSTATUS fast_wake_addr( const void *addr )
{
    int *futex;

    if (!use_futexes())
        return STATUS_NOT_IMPLEMENTED;

    futex = hash_addr( addr );

    InterlockedIncrement( futex );

    futex_wake( futex, INT_MAX );
    return STATUS_SUCCESS;
}

#else

NTSTATUS CDECL fast_RtlTryAcquireSRWLockExclusive( RTL_SRWLOCK *lock )
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS CDECL fast_RtlAcquireSRWLockExclusive( RTL_SRWLOCK *lock )
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS CDECL fast_RtlTryAcquireSRWLockShared( RTL_SRWLOCK *lock )
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS CDECL fast_RtlAcquireSRWLockShared( RTL_SRWLOCK *lock )
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS CDECL fast_RtlReleaseSRWLockExclusive( RTL_SRWLOCK *lock )
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS CDECL fast_RtlReleaseSRWLockShared( RTL_SRWLOCK *lock )
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS CDECL fast_RtlWakeConditionVariable( RTL_CONDITION_VARIABLE *variable, int count )
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS CDECL fast_wait_cv( RTL_CONDITION_VARIABLE *variable, const void *value, const LARGE_INTEGER *timeout )
{
    return STATUS_NOT_IMPLEMENTED;
}

static inline NTSTATUS fast_wait_addr( const void *addr, const void *cmp, SIZE_T size,
                                       const LARGE_INTEGER *timeout )
{
    return STATUS_NOT_IMPLEMENTED;
}

static inline NTSTATUS fast_wake_addr( const void *addr )
{
    return STATUS_NOT_IMPLEMENTED;
}

#endif


/***********************************************************************
 *           RtlWaitOnAddress   (NTDLL.@)
 */
NTSTATUS WINAPI RtlWaitOnAddress( const void *addr, const void *cmp, SIZE_T size,
                                  const LARGE_INTEGER *timeout )
{
    select_op_t select_op;
    NTSTATUS ret;
    timeout_t abs_timeout = timeout ? timeout->QuadPart : TIMEOUT_INFINITE;

    if (size != 1 && size != 2 && size != 4 && size != 8)
        return STATUS_INVALID_PARAMETER;

    if ((ret = fast_wait_addr( addr, cmp, size, timeout )) != STATUS_NOT_IMPLEMENTED)
        return ret;

    mutex_lock( &addr_mutex );
    if (!compare_addr( addr, cmp, size ))
    {
        mutex_unlock( &addr_mutex );
        return STATUS_SUCCESS;
    }

    if (abs_timeout < 0)
    {
        LARGE_INTEGER now;

        NtQueryPerformanceCounter( &now, NULL );
        abs_timeout -= now.QuadPart;
    }

    select_op.keyed_event.op     = SELECT_KEYED_EVENT_WAIT;
    select_op.keyed_event.handle = wine_server_obj_handle( keyed_event );
    select_op.keyed_event.key    = wine_server_client_ptr( addr );

    return server_select( &select_op, sizeof(select_op.keyed_event), SELECT_INTERRUPTIBLE,
                          abs_timeout, NULL, &addr_mutex, NULL );
}

/***********************************************************************
 *           RtlWakeAddressAll    (NTDLL.@)
 */
void WINAPI RtlWakeAddressAll( const void *addr )
{
    if (fast_wake_addr( addr ) != STATUS_NOT_IMPLEMENTED) return;

    mutex_lock( &addr_mutex );
    while (NtReleaseKeyedEvent( 0, addr, 0, &zero_timeout ) == STATUS_SUCCESS) {}
    mutex_unlock( &addr_mutex );
}

/***********************************************************************
 *           RtlWakeAddressSingle (NTDLL.@)
 */
void WINAPI RtlWakeAddressSingle( const void *addr )
{
    if (fast_wake_addr( addr ) != STATUS_NOT_IMPLEMENTED) return;

    mutex_lock( &addr_mutex );
    NtReleaseKeyedEvent( 0, addr, 0, &zero_timeout );
    mutex_unlock( &addr_mutex );
}
