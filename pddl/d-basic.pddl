(define (domain website)

    (:requirements :action-costs :typing :negative-preconditions :disjunctive-preconditions :conditional-effects)

    (:types 
        server ip - object
    )

    (:predicates 
        (BLOCKED ?ip - ip)
        (SERVICE_UNREACHABLE ?server - server)
        (RESTART_REQUIRED ?server - server)
        (SERVICE_SLOW ?server - server)
        (REQUEST_HEADER_TIMEOUT_FAST ?server - server)
        (REQUEST_RATE_HIGH_FROM_IP ?ip - ip)
        (SYSADMIN_ALERTED ?server)
    )

    (:functions 
        (total-cost)
        (RESTART_COST)
        (SLOW_CONNECTION_USERS)
        (EXPECTED_REVENUE)
        (REVENUE_IMPACT)
        (SYSADMIN_COST)
    )

    (:action block_ip
        :parameters (?ip - ip ?server - server)
        :precondition (and (REQUEST_RATE_HIGH_FROM_IP ?ip) (not (BLOCKED ?ip))) 
        :effect (and 
            (not (REQUEST_RATE_HIGH_FROM_IP ?ip))
            (BLOCKED ?ip)
            (not (SERVICE_UNREACHABLE ?server))
        )
    )

    (:action decrease_request_header_timeout
        :parameters (?server - server)
        :precondition (and (not (REQUEST_HEADER_TIMEOUT_FAST ?server))) 
        :effect (and 
            (increase (total-cost) (SLOW_CONNECTION_USERS))
            (REQUEST_HEADER_TIMEOUT_FAST ?server)
            (RESTART_REQUIRED ?server)
            (not (SERVICE_UNREACHABLE ?server))
        )
    )

    (:action restart_server
        :parameters (?server - server)
        :precondition (and 
            (RESTART_REQUIRED ?server)
        )
        :effect (and 
            (increase (total-cost) (RESTART_COST))
            (not (RESTART_REQUIRED ?server))
        )
    )

    (:action alert_sysadmin
        :parameters (?server - server)
        :precondition (SERVICE_UNREACHABLE ?server)
        :effect (and 
            (SYSADMIN_ALERTED ?server)
            (increase (total-cost) (SYSADMIN_COST))
        )
    )

    (:action do_nothing
        :parameters (?server - server)
        :precondition (not (SERVICE_SLOW ?server))
        :effect (and 
            (not(SERVICE_UNREACHABLE ?server))
        )
    )
)