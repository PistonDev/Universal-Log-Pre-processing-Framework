import re

reg_expressions = {

    # CEF:Version|Vendor|Product|DevVersion|SignatureID|Name|Severity|Extension
    "cef": r"""(?x)
        ^ [^{|]*?                          # optional syslog header (never contains '{' or '|')
        \b CEF: \d+                        # signature + format version
        (?: \| (?:[^|\\] | \\.)* ){6}      # Vendor|Product|Version|SigID|Name|Severity
        \|                                 # pipe that opens the key=value extension
    """,

    # LEEF:1.0|Vendor|Product|Version|EventID|attrs    (LEEF 2.0 adds a delimiter field)
    "leef": r"""(?x)
        ^ [^{|]*?                          # optional syslog header
        \b LEEF: \d+ (?: \. \d+ )?         # LEEF:1.0 / LEEF:2.0
        (?: \| (?:[^|\\] | \\.)* ){4}      # Vendor|Product|Version|EventID
        \|                                 # pipe that opens the attributes
    """,

    # ---------------- Vendor-specific formats ----------------

    # FortiGate key=value: date=... time=... devname="x" logid="0000000013" type="traffic" ...
    # Look-aheads, so the fields may appear in any order.
    "fortinet": r"""(?x)
        ^
        (?= .* \b logid = "? \d{10} \b )                    # 10-digit log id
        (?= .* \b type  = "? [a-z][a-z\-]* \b )             # traffic / utm / event / ...
        (?= .* \b (?: devname | devid ) = "? [\w.\-]+ )     # device identity
    """,

    # Palo Alto CSV syslog: 1,2023/09/29 10:00:00,001234567890,TRAFFIC,end,...
    "palo_alto": r"""(?x)
        ^ [^,]* ,                                           # (syslog header +) FUTURE_USE field
        \d{4}/\d{2}/\d{2} [ ] \d{2}:\d{2}:\d{2} ,           # receive time
        [^,]* ,                                             # serial number
        (?: TRAFFIC | THREAT | SYSTEM | CONFIG | URL | DATA | WILDFIRE
          | HIP-MATCH | HIPMATCH | GLOBALPROTECT | USERID | AUTHENTICATION
          | DECRYPTION | TUNNEL | SCTP | IP-TAG | IPTAG | CORRELATION | GTP ) ,
    """,

    # Check Point Log Exporter: [action:"Accept"; flags:"411908"; ifdir:"inbound"; ...]
    "checkpoint": r"""(?x)
        ^ [^{]*?                                            # optional syslog header
        \[ (?: [A-Za-z_][\w\-]* : " [^"]* " ; [ ]* ){2,}    # at least two key:"value"; pairs
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
        % [A-Z][A-Z0-9_]*                  # facility / product
        - (?: [a-z]+ - )?                  # optional context (ASA multi-context)
        [0-7] -                            # severity 0-7
        [A-Z0-9_]+ :                       # mnemonic or numeric message id
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
            \{ \s* " (?:[^"\\] | \\.)* " \s* :             # object whose first key is a string
          | \[ \s* \{ \s* " (?:[^"\\] | \\.)* " \s* :      # array of objects
          | [\[{] \s* $                                    # lone bracket on its own line
        )
    """,

    # XML: declaration, DOCTYPE, comment, opening tag (with attributes) or closing tag.
    # Tag names must start with a letter/underscore, so syslog "<134>" is NOT taken for XML.
    "xml": r"""(?x)
        ^ \s*
        (?:
            <\?xml \b [^>]* \?>                            # <?xml version="1.0"?>
          | <!DOCTYPE \b [^>]* >
          | <!--
          | < [A-Za-z_][\w.\-]* (?: : [A-Za-z_][\w.\-]* )? # <name> or <ns:name>
            (?: \s+ [\w.:\-]+ \s* = \s* (?: "[^"]*" | '[^']*' ) )*   # attributes
            \s* /? >
          | </ [A-Za-z_][\w.\-]* (?: : [\w.\-]+ )? \s* >   # </name>
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
        ^ \S+ [ ] \S+ [ ] \S+ [ ]                                    # host ident authuser
        \[ \d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [ ] [+-]\d{4} \] [ ]
        " [^"]* " [ ]                                                # "request line"
        \d{3} [ ] (?: \d+ | - )                                      # status, bytes
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
        (?: [.,] \d{1,9} )?                          # fractional seconds
        (?: Z | [+-]\d{2}:?\d{2} )?                  # timezone
        \s+ \[?
        (?: TRACE | DEBUG | INFO | NOTICE | WARN(?:ING)? | ERROR | SEVERE | CRITICAL | FATAL ) \b
    """,

    # ---------------- Generic fall-backs (keep LAST) ----------------

    # RFC 5424 syslog: <34>1 2003-10-11T22:14:15.003Z host app procid msgid ...
    "syslog_rfc5424": r"""(?x)
        ^ <\d{1,3}> \d{1,2} [ ]                                      # <PRI>VERSION
        (?: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2} (?: \.\d{1,6} )? (?: Z | [+-]\d{2}:\d{2} ) | - ) [ ]
        \S+ [ ] \S+ [ ] \S+ [ ] \S+                                  # host app procid msgid
    """,

    # RFC 3164 syslog (your original pattern, unchanged)
    "syslog" : r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+",

    # CSV: at least 3 fields; a field is "quoted, with ""escaped"" quotes" or unquoted.
    # Purely structural, so it is the weakest signal and comes very last.
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
