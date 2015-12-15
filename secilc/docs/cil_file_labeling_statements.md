File Labeling Statements
========================

filecon
-------

Define entries for labeling files. The compiler will produce these entries in a file called **`file_contexts`**`(5)` by default in the `cwd`. The compiler option `[-f|--filecontext <filename>]` may be used to specify a different path or file name.

**Statement definition:**

    (filecon "path" file_type context_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>filecon</code></p></td>
<td align="left"><p>The <code>filecon</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>path</code></p></td>
<td align="left"><p>A string representing the file path that may be in the form of a regular expression. The string must be enclosed within double quotes (e.g. <code>&quot;/this/is/a/path(/.*)?&quot;</code>)</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>file_type</code></p></td>
<td align="left"><p>A single keyword representing a file type in the <code>file_contexts</code> file as follows:</p>
<table>
<colgroup>
<col width="44%" />
<col width="55%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><strong>keyword</strong></p></td>
<td align="left"><p><strong>file_contexts entry</strong></p></td>
</tr>
<tr class="even">
<td align="left"><p><code>file</code></p></td>
<td align="left"><p><code>--</code></p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>dir</code></p></td>
<td align="left"><p><code>-d</code></p></td>
</tr>
<tr class="even">
<td align="left"><p><code>char</code></p></td>
<td align="left"><p><code>-c</code></p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>block</code></p></td>
<td align="left"><p><code>-b</code></p></td>
</tr>
<tr class="even">
<td align="left"><p><code>socket</code></p></td>
<td align="left"><p><code>-s</code></p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>pipe</code></p></td>
<td align="left"><p><code>-p</code></p></td>
</tr>
<tr class="even">
<td align="left"><p><code>symlink</code></p></td>
<td align="left"><p><code>-l</code></p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>any</code></p></td>
<td align="left"><p>no entry</p></td>
</tr>
</tbody>
</table></td>
</tr>
<tr class="even">
<td align="left"><p><code>context_id</code></p></td>
<td align="left"><p>The security context to be allocated to the file, which may be:</p>
<ul>
<li><p>A previously declared <code>context</code> identifier or an anonymous security context (<code>user role type levelrange</code>), the range MUST be defined whether the policy is MLS/MCS enabled or not.</p></li>
<li><p>An empty context list represented by <code>()</code> can be used to indicate that matching files should not be re-labeled. This will be interpreted as <code>&lt;&lt;none&gt;&gt;</code> within the <strong><code>file_contexts</code></strong><code>(5)</code> file.</p></li>
</ul></td>
</tr>
</tbody>
</table>

**Examples:**

These examples use one named, one anonymous and one empty context definition:

    (context runas_exec_context (u object_r exec low_low))

    (filecon "/system/bin/run-as" file runas_exec_context)
    (filecon "/dev/socket/wpa_wlan[0-9]" any u:object_r:wpa.socket:s0-s0)
    (filecon "/data/local/mine" dir ())

to resolve/build `file_contexts` entries of (assuming MLS enabled policy):

    /system/bin/run-as  -- u:object_r:runas.exec:s0
    /dev/socket/wpa_wlan[0-9]   u:object_r:wpa.socket:s0
    /data/local/mine -d <<none>>

fsuse
-----

Label filesystems that support SELinux security contexts.

**Statement definition:**

    (fsuse fstype fsname context_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>fsuse</code></p></td>
<td align="left"><p>The <code>fsuse</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>fstype</code></p></td>
<td align="left"><p>A single keyword representing the type of filesystem as follows:</p>
<ul>
<li><p><code>task</code> - For pseudo filesystems supporting task related services such as pipes and sockets.</p></li>
<li><p><code>trans</code> - For pseudo filesystems such as pseudo terminals and temporary objects.</p></li>
<li><p><code>xattr</code> - Filesystems supporting the extended attribute <code>security.selinux</code>. The labeling is persistent for filesystems that support extended attributes.</p></li>
</ul></td>
</tr>
<tr class="odd">
<td align="left"><p><code>fsname</code></p></td>
<td align="left"><p>Name of the supported filesystem (e.g. <code>ext4</code> or <code>pipefs</code>).</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>context_id</code></p></td>
<td align="left"><p>The security context to be allocated to the network interface.</p>
<p>A previously declared <code>context</code> identifier or an anonymous security context (<code>user role type levelrange</code>), the range MUST be defined whether the policy is MLS/MCS enabled or not.</p></td>
</tr>
</tbody>
</table>

**Examples:**

The [context](#context) identifiers are declared in the `file` namespace and the [`fsuse`](cil_file_labeling_statements.md#fsuse) statements in the global namespace:

    (block file
        (type labeledfs)
        (roletype object_r labeledfs)
        (context labeledfs_context (u object_r labeledfs low_low))

        (type pipefs)
        (roletype object_r pipefs)
        (context pipefs_context (u object_r pipefs low_low))
        ...
    )

    (fsuse xattr ex4 file.labeledfs_context)
    (fsuse xattr btrfs file.labeledfs_context)

    (fsuse task pipefs file.pipefs_context)
    (fsuse task sockfs file.sockfs_context)

    (fsuse trans devpts file.devpts_context)
    (fsuse trans tmpfs file.tmpfs_context)

genfscon
--------

Used to allocate a security context to filesystems that cannot support any of the [`fsuse`](cil_file_labeling_statements.md#fsuse) file labeling options. Generally a filesystem would have a single default security context assigned by [`genfscon`](cil_file_labeling_statements.md#genfscon) from the root `(/)` that would then be inherited by all files and directories on that filesystem. The exception to this is the `/proc` filesystem, where directories can be labeled with a specific security context (as shown in the examples).

**Statement definition:**

    (genfscon fsname path context_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>genfscon</code></p></td>
<td align="left"><p>The <code>genfscon</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>fsname</code></p></td>
<td align="left"><p>Name of the supported filesystem (e.g. <code>rootfs</code> or <code>proc</code>).</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>path</code></p></td>
<td align="left"><p>If <code>fsname</code> is <code>proc</code>, then the partial path (see examples). For all other types this must be ‘<code>/</code>’.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>context_id</code></p></td>
<td align="left"><p>A previously declared <code>context</code> identifier or an anonymous security context (<code>user role type levelrange</code>), the range MUST be defined whether the policy is MLS/MCS enabled or not.</p></td>
</tr>
</tbody>
</table>

**Examples:**

The [context](#context) identifiers are declared in the `file` namespace and the [`genfscon`](cil_file_labeling_statements.md#genfscon) statements are then inserted using the [`in`](cil_container_statements.md#in) container statement:

    (file
        (type rootfs)
        (roletype object_r rootfs)
        (context rootfs_context (u object_r rootfs low_low))

        (type proc)
        (roletype object_r proc)
        (context rootfs_context (u object_r proc low_low))
        ...
    )

    (in file
        (genfscon rootfs / rootfs_context)
        ; proc labeling can be further refined (longest matching prefix).
        (genfscon proc / proc_context)
        (genfscon proc /net/xt_qtaguid/ctrl qtaguid_proc_context)
        (genfscon proc /sysrq-trigger sysrq_proc_context)
        (genfscon selinuxfs / selinuxfs_context)
    )
