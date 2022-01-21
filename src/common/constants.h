#ifndef SRC_COMMON_CONSTANTS_H_
#define SRC_COMMON_CONSTANTS_H_

/**
 * @file
 * General purpose #defines, intended to minimize use of numerical constants
 * elsewhere in the code.
 */


/* -- Timeouts, defined by RFC 6146, section 4. */

/**
 * Minimum allowable session lifetime for UDP bindings, in seconds.
 */
#define UDP_MIN (2 * 60)
/**
 * Defined in the RFC as the minimum allowable default value for the session
 * lifetime of UDP bindings, in seconds. We use it as the actual default value.
 */
#define UDP_DEFAULT (5 * 60)
/**
 * Established connection idle timeout (in seconds).
 * In other words, the tolerance time for established and healthy TCP sessions.
 * If a connection remains idle for longer than this, then we expect it to
 * terminate soon.
 */
#define TCP_EST (2 * 60 * 60)
/**
 * Transitory connection idle timeout (in seconds).
 * In other words, the timeout of TCP sessions which are expected to terminate
 * soon.
 */
#define TCP_TRANS (4 * 60)
/**
 * Timeout of TCP sessions started from v4 which we're skeptical as to whether
 * they are going to make it to the established state.
 * Also the time a user has to manage a hole punch through Jool.
 * Measured in in seconds.
 * This value cannot be configured from the userspace app (this is on purpose).
 */
#define TCP_INCOMING_SYN (6)
/** Default session lifetime for ICMP bindings, in seconds. */
#define ICMP_DEFAULT (1 * 60)

/*
 * The timers will never sleep less than this amount of jiffies. This is because
 * I don't think we need to interrupt the kernel too much.
 *
 * 255 stands for TVR_SIZE - 1 (The kernel doesn't export TVR_SIZE).
 * Why that value? It's the maximum we can afford without cascading the timer
 * wheel when CONFIG_BASE_SMALL is false (https://lkml.org/lkml/2005/10/19/46).
 *
 * jiffies can be configured (http://man7.org/linux/man-pages/man7/time.7.html)
 * to be
 * - 0.01 seconds, which will make this minimum ~2.5 seconds.
 * - 0.004 seconds, which will make this minimum ~1 second.
 * - 0.001 seconds, which will make this minimum ~0.25 seconds.
 *
 * If you think this is dumb, you can always assign some other value, such as
 * zero.
 */
#define MIN_TIMER_SLEEP (255)

/* -- Config defaults -- */
#define DEFAULT_ADDR_DEPENDENT_FILTERING false
#define DEFAULT_FILTER_ICMPV6_INFO false
#define DEFAULT_DROP_EXTERNAL_CONNECTIONS false
#define DEFAULT_MAX_STORED_PKTS 10
#define DEFAULT_SRC_ICMP6ERRS_BETTER true
#define DEFAULT_F_ARGS 0b1011
#define DEFAULT_HANDLE_FIN_RCV_RST false
#define DEFAULT_BIB_LOGGING false
#define DEFAULT_SESSION_LOGGING false

#define DEFAULT_INSTANCE_ENABLED true
#define DEFAULT_RESET_TRAFFIC_CLASS false
#define DEFAULT_RESET_TOS false
#define DEFAULT_NEW_TOS 0
#define DEFAULT_LOWEST_IPV6_MTU 1280
#define DEFAULT_COMPUTE_UDP_CSUM0 false
#define DEFAULT_EAM_HAIRPIN_MODE EHM_INTRINSIC
#define DEFAULT_RANDOMIZE_RFC6791 true
#define DEFAULT_MTU_PLATEAUS { 65535, 32000, 17914, 8166, 4352, 2002, 1492, \
		1006, 508, 296, 68 }

/* -- IPv6 Pool -- */

#define WELL_KNOWN_PREFIX "64:ff9b::/96"

/**
 * RFC 6052's allowed prefix lengths.
 */
#define POOL6_PREFIX_LENGTHS { 32, 40, 48, 56, 64, 96 }



/* -- ICMP constants missing from icmp.h and icmpv6.h. -- */

/** Code 0 for ICMP messages of type ICMP_PARAMETERPROB. */
#define ICMP_PTR_INDICATES_ERROR 0
/** Code 2 for ICMP messages of type ICMP_PARAMETERPROB. */
#define ICMP_BAD_LENGTH 2


/* -- Netlink -- */

#define NETLINK_MULTICAST_FAMILY 22


#endif /* SRC_COMMON_CONSTANTS_H_ */
