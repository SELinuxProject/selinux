The SELinux Userspace Security Vulnerability Handling Process
===============================================================================
https://github.com/SELinuxProject/selinux

This document attempts to describe the processes through which sensitive
security relevant bugs can be responsibly disclosed to the SELinux userspace
project and how the project maintainers should handle these reports. Just like
the other SELinux userspace process documents, this document should be treated
as a guiding document and not a hard, unyielding set of regulations; the bug
reporters and project maintainers are encouraged to work together to address
the issues as best they can, in a manner which works best for all parties
involved.

### Reporting Problems

Note that issues that depend on attacker-controlled policy can be
reported as regular bugs to the public selinux@vger.kernel.org mailing
list and do not need to follow this process.

For serious problems or security vulnerabilities in the SELinux kernel code
please refer to the SELinux Kernel Subsystem Security Policy in the link below:

* https://github.com/SELinuxProject/selinux-kernel/blob/main/SECURITY.md

Problems with the SELinux userspace that are not suitable for
immediate public disclosure should be reported using
[GitHub private vulnerability reporting](https://github.com/SELinuxProject/selinux/security)
or emailed to the current SELinux userspace maintainers - the list is
below. We typically request at most a 90 day time period to address
the issue before it is made public, but we will make every effort to
address the issue as quickly as possible and shorten the disclosure
window.

* Petr Lautrbach, plautrba@redhat.com
* James Carter, jwcart2@gmail.com
  *  (GPG fingerprint) 4568 1128 449B 65F8 80C6  1797 3A84 A946 B4BA 62AE
* Paul Moore, paul@paul-moore.com
  *  (GPG fingerprint) 7100 AADF AE6E 6E94 0D2E  0AD6 55E4 5A5A E8CA 7C8A
* Stephen Smalley, stephen.smalley.work@gmail.com
  *  (GPG fingerprint) 578C 4211 832F 0A7E A2C5  A7C2 21A4 6E60 3F74 4ECF
* Jason Zaman, perfinion@gentoo.org
  *  (GPG fingerprint) 6319 1CE9 4183 0986 89CA  B8DB 7EF1 37EC 935B 0EAF
* Ondrej Mosnacek, omosnace@redhat.com

If unsure about whether an issue is in kernel or userspace, feel free
to send it to both the kernel and userspace maintainers and the
maintainers will handle it internally.

### Resolving Sensitive Security Issues

Upon disclosure of a bug, the maintainers should work together to investigate
the problem and decide on a solution. In order to prevent an early disclosure
of the problem, those working on the solution should do so privately and
outside of the traditional SELinux userspace development practices. One
possible solution to this is to leverage the GitHub "Security" functionality to
create a private development fork that can be shared among the maintainers, and
optionally the reporter. A placeholder GitHub issue may be created, but details
should remain extremely limited until such time as the problem has been fixed
and responsibly disclosed. If a CVE, or other tag, has been assigned to the
problem, the GitHub issue title should include the vulnerability tag once the
problem has been disclosed.

### Public Disclosure

Whenever possible, responsible reporting and patching practices should be
followed, including notification to the linux-distros and oss-security mailing
lists.

* https://oss-security.openwall.org/wiki/mailing-lists/distros
* https://oss-security.openwall.org/wiki/mailing-lists/oss-security

### Maintainer Process

This is the process maintainers will follow upon receiving a security notification.

1. Make sure all appropriate SELinux maintainers are notified. Regardless of
   which maintainer was initially contacted, others should be looped in. This
   may also include the kernel maintainers if relevant to the issue.
2. After an initial review of the issue, maintainers will agree on one person
   to be main point of contact. The response to the initial mail may come from a
   different maintainer. If the initial mail was PGP signed/encrypted, the
   replies will also be PGP signed/encrypted with one of the above keys.
3. Maintainers will work together in private to verify and fix the issue. For
   larger fixes, this might involve a github private fork within a draft github
   security advisory.
4. Maintainers will prepare the fix as soon as reasonable. Maintainers may
   invite the reporter to the draft security advisory or private fork to help
   verifying the fix.
5. We will aim to release the fix publicly quickly, but may request an embargo
   period up to 90 days if the complexity of the issue requires it or if
   severity of the issue requires coordinated rollout amongst distros.
6. Public disclosure will involve pushing the fix to the public repo and
   publishing the security advisory on Github and to the mailing list.
