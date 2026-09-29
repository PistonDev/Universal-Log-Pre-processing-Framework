import re

reg_expressions = {

    # CEF:Version|Vendor|Product|DevVersion|SignatureID|Name|Severity|Extension
    "cef": r"""(?x)
        ^ [^{|]*?  
        \b CEF: \d+
        (?: \| (?:[^|\\] | \\.)* ){6}
        \|
    """,

    # LEEF:1.0|Vendor|Product|Version|EventID|attrs    (LEEF 2.0 adds a delimiter field)
    "leef": r"""(?x)
        ^ [^{|]*?
        \b LEEF: \d+ (?: \. \d+ )?
        (?: \| (?:[^|\\] | \\.)* ){4}
        \|
    """,

    # ---------------- Vendor-specific formats ----------------

    # FortiGate key=value: date=... time=... devname="x" logid="0000000013" type="traffic" ...
    "fortinet": r"""(?x)
        ^
        (?= .* \b logid = "? \d{10} \b )
        (?= .* \b type  = "? [a-z][a-z\-]* \b )
        (?= .* \b (?: devname | devid ) = "? [\w.\-]+ )
    """,

    # Palo Alto CSV syslog: 1,2023/09/29 10:00:00,001234567890,TRAFFIC,end,...
    "palo_alto": r"""(?x)
        ^ [^,]* ,
        \d{4}/\d{2}/\d{2} [ ] \d{2}:\d{2}:\d{2} ,
        [^,]* ,
        (?: TRAFFIC | THREAT | SYSTEM | CONFIG | URL | DATA | WILDFIRE
          | HIP-MATCH | HIPMATCH | GLOBALPROTECT | USERID | AUTHENTICATION
          | DECRYPTION | TUNNEL | SCTP | IP-TAG | IPTAG | CORRELATION | GTP ) ,
    """,

    # Check Point Log Exporter: [action:"Accept"; flags:"411908"; ifdir:"inbound"; ...]
    "checkpoint": r"""(?x)
        ^ [^{]*
        \[ (?: [A-Za-z_][\w\-]* : " [^"]* " ; [ ]* ){2,}
    """,

    # SonicWall: id=firewall sn=0006B1234567 time="2023-09-29 10:00:00" fw=... msg="..."
    "sonicwall": r"""(?x)
        ^ [^{]*?
        \b id=firewall [ ]+ sn=\w+ [ ]+ time=
    """,

    # Cisco IOS / ASA / FTD: %FACILITY-[context-]SEVERITY-MNEMONIC:
    # e.g. %ASA-6-302013:   %LINK-3-UPDOWN:   %ASA-session-6-302013:
    "cisco": r"""(?x)
        ^ [^{|]*?
        % [A-Z][A-Z0-9_]*
        - (?: [a-z]+ - )?
        [0-7] -
        [A-Z0-9_]+ :
    """,

    # Juniper Junos: RT_FLOW_SESSION_CREATE ... or structured data [junos@2636.1.1.1.2.129 ...]
    "juniper": r"""(?x)
        ^ [^{]*?
        (?: \b RT_(?: FLOW | IDS | UTM | SCREEN | IDP | AAMW | SECINTEL ) \w*
          | \[ junos@2636 \.
        )
    """,

    # ---------------- Generic structured formats ----------------

    # JSON / NDJSON: {"key": ...   [{"key": ...   or a lone '{' / '[' (pretty-printed)
    "json": r"""(?x)
        ^ \s*
        (?:
            \{ \s* " (?:[^"\\] | \\.)* " \s* :
          | \[ \s* \{ \s* " (?:[^"\\] | \\.)* " \s* :
          | [\[{] \s* $
        )
    """,

    "xml": r"""(?x)
        ^ \s*
        (?:
            <\?xml \b [^>]* \?>
          | <!DOCTYPE \b [^>]* >
          | <!--
          | < [A-Za-z_][\w.\-]* (?: : [A-Za-z_][\w.\-]* )?
            (?: \s+ [\w.:\-]+ \s* = \s* (?: "[^"]*" | '[^']*' ) )*
            \s* /? >
          | </ [A-Za-z_][\w.\-]* (?: : [\w.\-]+ )? \s* >
        )
    """,

    # ---------------- Application-specific schemas ----------------

    # Zeek (Bro) TSV header: #separator \x09 / #fields<TAB>ts<TAB>uid ...
    "zeek": r"""(?x)
        ^ \# (?: separator | set_separator | empty_field | unset_field
               | path | open | fields | types | close ) \b
    """,

    # W3C extended log (IIS, Exchange, ...): #Software: / #Version: / #Date: / #Fields:
    "w3c_extended": r"""(?x)
        ^ \# (?: Software | Version | Date | Fields ) : [ ]
    """,

    # Kubernetes klog: I0929 10:00:00.123456       1 main.go:42] message
    "k8s_klog": r"""(?x)
        ^ [IWEF] \d{4} [ ] \d{2}:\d{2}:\d{2}\.\d{6}
        \s+ \d+ \s+ \S+ : \d+ \]
    """,

    # Apache / nginx access log (Common + Combined):
    #   127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326
    "web_access": r"""(?x)
        ^ \S+ [ ] \S+ [ ] \S+ [ ]
        \[ \d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [ ] [+-]\d{4} \] [ ]
        " [^"]* " [ ]
        \d{3} [ ] (?: \d+ | - )
    """,

    # Apache error log (your original pattern, unchanged)
    "apache" : r"^\[.*\] \[(notice|error|warn|info|debug)\]",

    # Python logging default format: ERROR:root:message
    "python_logging": r"""(?x)
        ^ (?: DEBUG | INFO | WARNING | ERROR | CRITICAL ) : [\w.\-]+ :
    """,

    # Java / log4j / logback / most app loggers:
    #   2023-09-29 10:00:00,123 INFO ...      2023-09-29T10:00:00.123Z ERROR ...
    "app_timestamp_level": r"""(?x)
        ^ \d{4}-\d{2}-\d{2} [T ] \d{2}:\d{2}:\d{2}
        (?: [.,] \d{1,9} )?
        (?: Z | [+-]\d{2}:?\d{2} )?
        \s+ \[?
        (?: TRACE | DEBUG | INFO | NOTICE | WARN(?:ING)? | ERROR | SEVERE | CRITICAL | FATAL ) \b
    """,

    # ---------------- Generic fall-backs (keep LAST) ----------------

    # RFC 5424 syslog: <34>1 2003-10-11T22:14:15.003Z host app procid msgid ...
    "syslog_rfc5424": r"""(?x)
        ^ <\d{1,3}> \d{1,2} [ ]
        (?: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2} (?: \.\d{1,6} )? (?: Z | [+-]\d{2}:\d{2} ) | - ) [ ]
        \S+ [ ] \S+ [ ] \S+ [ ] \S+
    """,

    # RFC 3164 syslog (your original pattern, unchanged)
    "syslog" : r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+",

    "csv": r"""(?x)
        ^
        (?: " (?:[^"] | "")* " | [^,"\r\n]* )                        # first field
        (?: , (?: " (?:[^"] | "")* " | [^,"\r\n]* ) ){2,}            # 2+ further fields
        $
    """,
}

class DetectFile:
    def __init__(self, data: str):
        self.data = data

    def detect(self) -> str:
        lines = self.data.splitlines()

        for line in lines:

            for source in reg_expressions:
                if re.match(reg_expressions[source], line):
                    return source
        return ""