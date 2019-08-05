# Contributing to SELinux

Contributing to the SELinux userspace project is a similar process to
other open source projects. Bug reports, new features to the existing
code, additional tools, or updated documentation are all welcome.

You can find a list of open issues where you might contribute to the SELinux kernel code at
https://github.com/SELinuxProject/selinux-kernel/issues or to the SELinux userspace code at
https://github.com/SELinuxProject/selinux/issues.

See the selinuxproject.org [user resources
page](http://selinuxproject.org/page/User_Resources) for more
information on mailing lists, documentation, and other resources.

## Reporting Bugs

All bugs and patches should be submitted to the [SELinux mailing
list](https://lore.kernel.org/selinux) at selinux@vger.kernel.org.

When reporting bugs please include versions of SELinux related libraries and
tools (libsepol, libselinux, libsemanage, checkpolicy). If you are
using a custom policy please include it as well.

## Compiling

There are a number of dependencies required to build the userspace
tools/libraries. On a Fedora system you can install them with yum:

    # yum install audit-libs-devel bison bzip2-devel dbus-devel dbus-glib-devel flex flex-devel flex-static glib2-devel libcap-devel libcap-ng-devel pam-devel pcre-devel python-devel setools-devel swig ustr-devel

The tools and libraries can be built and installed under a private directory from the top level with make, e.g.

    $ make DESTDIR=~/obj install install-pywrap

## Contributing Code

After obtaining the code of the repository (see below), create a patch
against the repository, and post that patch to the [SELinux mailing
list](https://lore.kernel.org/selinux) at selinux@vger.kernel.org. When preparing
patches, please follow these guidelines:

-   Patches should apply with -p1
-   Must apply against HEAD of the master branch
-   Separate large patches into logical patches
-   Patch descriptions must end with your "Signed-off-by" line. This means your
    code meets the Developer's certificate of origin, see below.

When adding new, large features or tools it is best to discuss the
design on the mailing list prior to submitting the patch.

## Development Repository

Git is a modern source code management system. For more information
about Git please see the Git website.

To get an anonymous checkout of the SELinux userland repository you can
run:

    $ git clone https://github.com/SELinuxProject/selinux.git

# Developer Certificate of Origin

    Developer's Certificate of Origin 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I
        have the right to submit it under the open source license
        indicated in the file; or

    (b) The contribution is based upon previous work that, to the best
        of my knowledge, is covered under an appropriate open source
        license and I have the right under that license to submit that
        work with modifications, whether created in whole or in part
        by me, under the same open source license (unless I am
        permitted to submit under a different license), as indicated
        in the file; or

    (c) The contribution was provided directly to me by some other
        person who certified (a), (b) or (c) and I have not modified
        it.

    (d) I understand and agree that this project and the contribution
        are public and that a record of the contribution (including all
        personal information I submit with it, including my sign-off) is
        maintained indefinitely and may be redistributed consistent with
        this project or the open source license(s) involved.
