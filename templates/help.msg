Current hostname: {{ hostname }}

OOB types:
    /exfil/query - exfiltrate data via query string
    /exfil/post - exfiltrate data via post body

Codecs:
    plain - plaintext
    url - decode URL encoding
    b64 - decode Base64 encoding
    b64u - decode consequently with URL encoding and Base64

Example:
    {{ hostname }}/exfil/query?data=SGVsbG8%3D&decoder=b64u – decodes to "Hello"

Available routes:
{% for route in routes %}
    {{ route[0] }}
{% end %}