(define (problem {{data.name}})
	(:domain {{data.domain}})
    (:objects 
		{{ data.objects['servers']|join(' ', 'name')}} - server
		{{ data.objects['ips']|join(' ', 'name')}} - ip
    )
    (:init
	{% for p in data.predicates %}
		({{p|join(" ")}})
	{% endfor %}
    
    {% for function_assignment in data.function_values %}
        (=({% for e in function_assignment %}{% if not loop.last %}{{e}} {% else %}){{-e-}}{% endif %}{% endfor %})
	{% endfor %}
	)

    (:goal 
		(or 
			(and
			{% for goal in data.goal%}
				({{goal|join(" ")}})
			{% endfor %}
			(not (RESTART_REQUIRED apache2))
			(not (SERVICE_UNREACHABLE apache2))
			)
			(and 
				(SYSADMIN_ALERTED apache2)
			)
		)
	)

    (:metric minimize (total-cost))
)