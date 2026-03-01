# Finite State Machine

[Back to ssf README](../README.md)

Event-driven finite state machine framework with hierarchical state support and optional RTOS integration.

## Finite State Machine Framework

The state machine framework allows you to create reliable and efficient state machines.

Unless SSF_SM_CONFIG_ENABLE_THREAD_SUPPORT is enabled, all event generation and execution of task handlers for ALL state machines must be done in a single thread of execution.
Calling into the state machine interface from two difference execution contexts is not supported and will eventually lead to problems.
There is a lot that can be said about state machines in general and this one specifically, and I will continue to add to this documentation in the future.

Here's a simple example:

```
/* ssfport.h */
...

/* --------------------------------------------------------------------------------------------- */
/* Configure ssfsm's state machine interface                                                     */
/* --------------------------------------------------------------------------------------------- */
/* Maximum number of simultaneously queued events for all state machines. */
#define SSF_SM_MAX_ACTIVE_EVENTS (5u)

/* Maximum number of simultaneously running timers for all state machines. */
#define SSF_SM_MAX_ACTIVE_TIMERS (2u)

/* Defines the state machine identifers. */
typedef enum
{
    SSF_SM_MIN = -1,
    SSF_SM_STATUS_LED,
    SSF_SM_MAX
} SSFSMList_t;

typedef enum
{
    /* Defines the event identifiers for all state machines. */
    SSF_SM_EVENT_MIN = -1,
    /* Required SSF events */
    SSF_SM_EVENT_ENTRY,  /* Signalled on entry to state handler */
    SSF_SM_EVENT_EXIT,   /* Signalled on exit of state handler */
    SSF_SM_EVENT_SUPER,  /* Signalled to determine parent of current state handler */
                         /* Usually handled in default case with SSF_SM_SUPER() */
                         /* macro. If no parent then SSF_SM_SUPER() is not */
                         /* required or must be called with NULL */
                         /* Super states may not have a parent super state */
    /* User defined events */
    SSF_SM_EVENT_STATUS_RX_DATA,
    SSF_SM_EVENT_STATUS_LED_TIMER_TOGGLE,
    SSF_SM_EVENT_STATUS_LED_TIMER_IDLE,
    SSF_SM_EVENT_MAX
} SSFSMEventList_t;

/* main.c */
...

/* State handler prototypes */
static void StatusLEDIdleHandler(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                                 SSFVoidFn_t *superHandler);
static void StatusLEDBlinkHandler(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                                  SSFVoidFn_t *superHandler);

static void StatusLEDIdleHandler(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                                 SSFVoidFn_t *superHandler)
{
    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        STATUS_LED_OFF();
        break;
    case SSF_SM_EVENT_EXIT:
        break;
    case SSF_SM_EVENT_STATUS_RX_DATA:
        SSFSMTran(StatusLEDBlinkHandler);
        break;
    default:
        break;
    }
}

static void StatusLEDBlinkHandler(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                                  SSFVoidFn_t *superHandler)

{
    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        SSFSMStartTimer(SSF_SM_EVENT_STATUS_LED_TIMER_TOGGLE, 0);
        SSFSMStartTimer(SSF_SM_EVENT_STATUS_LED_TIMER_IDLE, SSF_TICKS_PER_SEC * 10);
        break;
    case SSF_SM_EVENT_EXIT:
        break;
    case SSF_SM_EVENT_STATUS_LED_TIMER_TOGGLE:
        STATUS_LED_TOGGLE();
        SSFSMStartTimer(SSF_SM_EVENT_STATUS_LED_TIMER_TOGGLE, SSF_TICKS_PER_SEC);
        break;
    case SSF_SM_EVENT_STATUS_LED_TIMER_IDLE:
        SSFSMTran(StatusLEDIdleHandler);
        break;
    default:
        break;
    }
}

void main(void)
{

    /* Initialize state machine framework */
    SSFSMInit(SSF_SM_MAX_ACTIVE_EVENTS, SSF_SM_MAX_ACTIVE_TIMERS);

    /* Initialize status LED state machine */
    SSFSMInitHandler(SSF_SM_STATUS_LED, StatusLEDIdleHandler);

    while (true)
    {
        if (ReceivedMessage())
        {
            SSFSMPutEvent(SSF_SM_STATUS_LED, SSF_SM_EVENT_STATUS_RX_DATA);
        }
        SSFSMTask(NULL);
    }
...
```

The state machine framework is first initialized. Then the state machine for the Status LED is initialized, which causes the ENTRY action of the StatusLEDIdleHandler() to be executed, this turns off the LED.

Then main goes into its superloop that checks for a message begin received. When a message is received it will signal SSF_SM_EVENT_STATUS_RX_DATA. The idle handler will trigger a state transition to the StatusLEDBlinkHandler(). The state transition causes an EXIT event for the idle handler, AND an entry event for the blink handler.

On ENTRY the blink handler starts two timers. The SSF_SM_EVENT_STATUS_LED_TIMER_TOGGLE timer is set to go off immediately, and the SSF_SM_EVENT_STATUS_LED_TIMER_IDLE timer is set to go off in 10 seconds. When the SSF_SM_EVENT_STATUS_LED_TIMER_TOGGLE expires the status LED is toggled and the SSF_SM_EVENT_STATUS_LED_TIMER_TOGGLE timer is setup to fire again in 1 second. This cause the LED to blink.

If additional SSF_SM_EVENT_STATUS_RX_DATA events are signaled while in the toggle state they are ignored.

After 10 seconds the SSF_SM_EVENT_STATUS_LED_TIMER_IDLE timer expires and triggers a state transition to the idle state. First the EXIT event in the blink handler is executed automatically by the framework, followed by the ENTRY event in the idle handler that turns off the status LED.

The framework automatically stops all timers associated with a state machine when a state transition occurs. This is why it is not necessary to explicitly stop the SSF_SM_EVENT_STATUS_LED_TIMER_TOGGLE timer.

If you need to run the framework in a multi-threaded environment do the following:

-   Enable SSF_SM_CONFIG_ENABLE_THREAD_SUPPORT in ssfport.h
-   Implement the SSF*SM_THREAD_SYNC*\* macros using an OS mutext primitive.
-   Implement the SSF*SM_WAKE_SYNC*\* macros using an OS counting semaphore primitive. The unit test expects the maximum count to be capped at 1.
-   Implement an OS exection context (a task, thread, process, etc.) that initializes the framework and all the state machines. Then call SSFSMTask() throttled by SSF_SM_THREAD_WAKE_WAIT() with the timeout returned from SSFSMTask().
-   SSFSMTask() should normally execute as a high priority system task since it will execute quickly and block until a timer expires or an event is signalled.
-   Only SSFSMPutEventData() and SSFSMPutEvent() may be safely invoked from other execution contexts. Event signalling is allowed from interrupts when the OS synchronization primitives support such use.

Out of the box Windows supports the state machine framework in multi-threaded environments.
And, there is a pthread implementation for OS X and Linux that supports the state machine framework in multi-threaded environments.
OS X does not support CLOCK_MONOTONIC for pthread_cond_timedwait() so set SSF_SM_THREAD_PTHREAD_CLOCK_MONOTONIC to 0. Be aware that a system time change could cause unexpected behavior.
Another note on the pthread port: Contrary to standard pthreads docs, neither OS X or Linux return ETIMEDOUT from pthread_cond_timedwait() when a timeout occurred, this is something I intend to investigate.

Here's pseudocode for an OS thread initializing and running the framework, and demonstrating event generation from a different thread:

```
void OSThreadSSFSM(void *arg)
{
    SSFSMTimeout_t to;

    /* Initialize state machine framework */
    SSFSMInit(SSF_SM_MAX_ACTIVE_EVENTS, SSF_SM_MAX_ACTIVE_TIMERS);

    /* Initialize status LED state machine */
    SSFSMInitHandler(SSF_SM_STATUS_LED, StatusLEDIdleHandler);

    while (true)
    {
        SSFSMTask(&to);
        SSF_SM_THREAD_WAKE_WAIT(to);
    }
}

...

void OSThreadEventGenerator(void *arg)
{
    ...

    while (true)
    {
        if (ReceivedMessage())
        {
            SSFSMPutEvent(SSF_SM_STATUS_LED, SSF_SM_EVENT_STATUS_RX_DATA);
        }
    }
}
```

The state machine framework also support 1-level of hierarchical state nesting. To designate a state to have a parent state simply use the SSF_SM_SUPER() macro in the default case of a state handler's event switch statement. The framework is able to automatically determine the state relationships by probing the default case statment. Parent and child state handlers are functionally identical except that a parent state handler cannot use the SSF_SM_SUPER() macro to name another state handler as its parent. When the child is the current state and does not handle an event, the event will be sent to the parent handler for processing. Both parent and child states can be the current state. When multiple children have the same parent they can can share the same core behaviors, and focus on just handling events which are different from the shared parent. This helps to reduce redundancy between state handlers.

```
static void ChildHandler(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                         SSFVoidFn_t *superHandler);
static void ParentHandler(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                          SSFVoidFn_t *superHandler);

static void ChildHandler(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                         SSFVoidFn_t *superHandler)
{
    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        STATUS_LED_OFF();
        break;
    case SSF_SM_EVENT_EXIT:
        break;
    case SSF_SM_EVENT_CHILD:
        /* Do something specific to the child state */
        break;
    default:
        SSF_SM_SUPER(ParentHandler);
        break;
    }
}

static void ParentHandler(SSFSMEventId_t eid, const SSFSMData_t *data, SSFSMDataLen_t dataLen,
                          SSFVoidFn_t *superHandler)
{
    switch (eid)
    {
    case SSF_SM_EVENT_ENTRY:
        break;
    case SSF_SM_EVENT_EXIT:
        break;
    case SSF_SM_EVENT_PARENT:
        /* Do something specific to the parent state */
        break;
    default:
        break;
    }
}

...

/* Initialize state machine framework */
SSFSMInit(SSF_SM_MAX_ACTIVE_EVENTS, SSF_SM_MAX_ACTIVE_TIMERS);

/* Initialize status LED state machine */
SSFSMInitHandler(SSF_SM_CHILD_PARENT, ChildHandler);
```

If the initial state is ChildHandler() then the ParentHandler() SSF_SM_EVENT_ENTRY clause followed by the ChildHandler() SSF_SM_EVENT_ENTRY clause will be run during initialization. If SSF_SM_EVENT_CHILD occurs then the ChildHandler() will handle the event and the ParentHandler() will not run. However if SSF_SM_EVENT_PARENT occurs, ChildHandler() will be called and execute the default clause, which redirects the event to be processed by ParentHandler(). The framework handles all state transition permutations and will properly exit and enter child and parent states as necessary.
