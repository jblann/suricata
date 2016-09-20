Meta-settings
=============

Meta-settings have no effect on Suricata's inspection; they have an
effect on the way Suricata reports events.

msg (message)
-------------

The keyword msg gives more information about the signature and the
possible alert.  The first part shows the filename of the
signature. It is a convention that part is written in uppercase
characters.

The format of msg is::

 msg: “...”;

Example::

  msg:"ATTACK-RESPONSES 403 Forbidden";
  msg:"ET EXPLOIT SMB-DS DCERPC PnP bind attempt";

*It is a convention that msg is always the first keyword of a signature.*

Another example of msg in a signature:

  alert tcp $HOME_NET any -> $EXTERNAL_NET any (**msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)";** flow:established,to_server; content:"NICK "; depth:5; content:"USA"; within:10; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; rev:5;)

In this example the red, bold-faced part is the msg.

Sid (signature id)
------------------

The keyword sid gives every signature its own id. This id is stated
with a number.

The format of sid is::

  sid:123;

Example of sid in a signature:

  alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)"; flow:established,to_server; content:"NICK "; depth:5; content:"USA"; within:10; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; **sid:2008124;** rev:5;)

Rev (Revision)
--------------

The sid keyword is almost every time accompanied by rev. Rev
represents the version of the signature. If a signature is modified,
the number of rev will be incremented by the signature writers.

The format of rev is::

 rev:123;

*It is a convention that sid comes before rev, and both are the last of
all keywords.*

Example of rev in a signature:

  alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)"; flow:established,to_server; content:"NICK "; depth:5; content:"USA"; within:10; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; **rev:5;**)

Gid (group id)
--------------

The gid keyword can be used to give different groups of signatures
another id value (like in sid). Suricata uses by default gid 1. It is
possible to modify this. It is not usual that it will be changed, and
changing it has no technical implications. You can only notice it in
the alert.

  10/01/2014-05:14:43.926704  [**] [**1**:2016903:5] ET USER_AGENTS Suspicious User-Agent (DownloadMR) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 192.168.81.10:1032 -> 95.211.39.161:80

This is an example from the fast.log.  In the part [1:2008124:2], 1 is
the gid (2008124 is the the sid and 2 the rev).

Classtype
---------

The classtype keyword gives information about the classification of
rules and alerts. It consists of a short name, a long name and a
priority. It can tell for example whether a rule is just informational
or is about a hack etcetera. For each classtype, the
classification.config has a priority which will be used in the rule.

*It is a convention that classtype comes before sid and rev and after
the rest of the keywords.*

Example classtype::

  config classification: web-application-attack,Web Application Attack,1
  config classification: not-suspicious,Not Suspicious Traffic,3

============== =================================== ======================
Signature      classification.config               Alert
============== =================================== ======================
web-attack     web-attack, Web Application Attack, Web Application Attack
               priority:1
not-suspicious not-suspicious, Not Suspiscious     Not Suspicious Traffic
               Traffic, priority:3
============== =================================== ======================

In the above table you see how classtype appears in signatures, the
classification.config and the alert.

Another example of classtype in a signature:

  alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)" flow:established,to_server; content:"NICK "; depth:5; content:"USA"; within:10; reference:url,doc.emergingthreats.net/2008124; **classtype:trojan-activity;** sid:2008124; rev:5;)

Reference
---------

The reference keywords direct to places where information about the
signature and about the problem the signature tries to address, can be
found. The reference keyword can appear multiple times in a signature.
This keyword is meant for signature-writers and analysts who
investigate why a signature has matched. It has the following format::

  reference: url, www.info.nl

In this example url is the type of reference. After that comes the
actual reference (notice here you can not use http before the url).

There are different types of references:

=========          ===============================================
system             URL Prefix
=========          ===============================================
bugtraq            ``http://www.securityfocus.com/bid``
cve                ``http://cve.mitre.org/cgi-bin/cvename.cgi?name=``
nessus             ``http://cgi.nessus.org/plugins/dump.php3?id=``
arachnids          ``http://www.whitehats.com/info/IDS``
mcafee             ``http://vil.nai.com/vil/dispVirus.asp?virus_k=``
url                ``http://``
=========          ===============================================

*Note that ararchnids is no longer available but may still be
encountered in signatures.*

For example bugtraq will be replaced by the full url::

  reference: bugtraq, 123; http://www.securityfocus.com/bid

Example of reference in a signature:

  alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)" flow:established,to_server; content:"NICK "; depth:5; content:"USA"; within:10; **reference:url,doc.emergingthreats.net/2008124;** classtype:trojan-activity; sid:2008124; rev:5;)

Priority
--------

The priority keyword comes with a mandatory numeric value which can
range from 1 till 255. The numbers 1 to 4 are most often used.
Signatures with a higher priority will be examined first. The highest
priority is 1.  Normally signatures have already a priority through
class type. This can be overruled with the keyword priority.  The
format of priority is::

  priority:1;

Metadata
--------

Suricata ignores the words behind meta data.
Suricata supports this keyword because it is part of the signature language.
The format is::

  metadata:...;
