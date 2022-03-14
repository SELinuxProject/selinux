CIL Information
===============

1.  Not all possible alternate statement permutations are shown, however there should be enough variation to work out any other valid formats. There is also an example [`policy.cil`](../test/policy.cil#example-policy) file in the test directory.

2.  The MLS components on contexts and user statements must be declared even if the policy does not support MCS/MLS.

3.  The CIL compiler will not build a policy unless it also has as a minimum: one [`allow`](cil_access_vector_rules.md#allow) rule, one [`sid`](cil_sid_statements.md#sid), [`sidorder`](cil_sid_statements.md#sidorder) and [`sidcontext`](cil_sid_statements.md#sidcontext) statement.

4.  The role `object_r` must be explicitly associated to contexts used for labeling objects. The original **`checkpolicy`**`(8)` and **`checkmodule`**`(8)` compilers did this by default - CIL does not.

5.  Be aware that CIL allows [`class`](cil_class_and_permission_statements.md#class) statements to be declared in a namespace, however the policy author needs to note that applications (and the kernel) generally reference a class by its well known class identifier (e.g. `zygote`) however if declared in a namespace (e.g. `(block zygote (class zygote (...)))` or `(block zygote (class class (...)))`) it would be prefixed with that namespace (e.g. `zygote.zygote` or `zygote.class`). Unless the application / kernel code was updated the class would never be resolved, therefore it is recommended that classes are declared in the global namespace.

6.  Where possible use [`typeattribute`](cil_type_statements.md#typeattribute)'s when defining source/target [`allow`](cil_access_vector_rules.md#allow) rules instead of multiple [`allow`](cil_access_vector_rules.md#allow) rules with individual [`type`](cil_type_statements.md#type)'s. This will lead to the generation of much smaller kernel policy files.

7.  The [](http://github.com/SELinuxProject/cil/wiki) site explains the language however some of the statement definitions are dated.

Declarations
------------

Declarations may be named or anonymous and have three different forms:

1.  Named declarations - These create new objects that introduce a name or identifier, for example:

    `(type process)` - creates a [`type`](cil_type_statements.md#type) with an identifier of `process`.

    `(typeattribute domain)` - creates a [`typeattribute`](cil_type_statements.md#typeattribute) with an identifier of `domain`.

    `(class file (read write))` - creates a [`class`](cil_class_and_permission_statements.md#class) with an identifier of `file` that has `read` and `write` permissions associated to it.

    The list of declaration type statement keywords are:

    block
    optional
    common
    class
    classmap
    classmapping
    sid
    user
    role
    roleattribute
    type
    classpermission
    classpermissionset
    typeattribute
    typealias
    tunable
    sensitivity
    sensitivityalias
    category
    categoryalias
    categoryset
    level
    levelrange
    context
    ipaddr
    macro
    policycap

2.  Explicit anonymous declarations - These are currently restricted to IP addresses where they can be declared directly in statements by enclosing them within parentheses e.g. `(127.0.0.1)` or `(::1)`. See the [Network Labeling Statements](#network_labeling) section for examples.

3.  Anonymous declarations - These have been previously declared and the object already exists, therefore they may be referenced by their name or identifier within statements. For example the following declare all the components required to specify a context:

    ```secil
        (sensitivity s0)
        (category c0)
        (role object_r)

        (block unconfined
            (user user)
            (type object)
        )
    ```

    now a [`portcon`](cil_network_labeling_statements.md#portcon) statement can be defined that uses these individual components to build a context as follows:

    ```secil
        (portcon udp 12345 (unconfined.user object_r unconfined.object ((s0) (s0(c0)))))
    ```

Definitions
-----------

Statements that build on the objects, for example:

-   `(typeattributeset domain (process))` - Adds the [`type`](cil_type_statements.md#type) '`process`' to the [`typeattribute`](cil_type_statements.md#typeattribute) '`domain`'.

-   `(allow domain process (file (read write))))` - Adds an [`allow`](cil_access_vector_rules.md#allow) rule referencing `domain`, `process` and the `file class`.

Definitions may be repeated many times throughout the policy. Duplicates will resolve to a single definition during compilation.

Symbol Character Set
--------------------

Symbols (any string not enclosed in double quotes) must only contain alphanumeric `[a-z A-Z] [0-9]` characters plus the following special characters: `\.@=/-_$%@+!|&^:`

However symbols are checked for any specific character set limitations, for example:

-   Names or identifiers must start with an alpa character `[a-z A-Z]`, the remainder may be alphanumeric `[a-z A-Z] [0-9]` characters plus underscore `[_]` or hyphen `[-]`.

-   IP addresses must conform to IPv4 or IPv6 format.

-   Memory, ports, irqs must be numeric `[0-9]`.

String Character Set
--------------------

Strings are enclosed within double quotes (e.g. `"This is a string"`), and may contain any character except the double quote (").

Comments
--------

Comments start with a semicolon '`;`' and end when a new line is started.

Namespaces
----------

CIL supports namespaces via containers such as the [`block`](cil_container_statements.md#block) statement. When a block is resolved to form the parent / child relationship a dot '`.`' is used, for example the following [`allow`](cil_access_vector_rules.md#allow) rule:

```secil
    (block example_ns
        (type process)
        (type object)
        (class file (open read write getattr))

        (allow process object (file (open read getattr)))
    )
```

will resolve to the following kernel policy language statement:

```
    allow example_ns.process example_ns.object : example_ns.file { open read getattr };
```

Global Namespace
----------------

CIL has a global namespace that is always present. Any symbol that is declared outside a container is in the global namespace. To reference a symbol in global namespace, the symbol should be prefixed with a dot '`.`' as shown in the following example:

```secil
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ; This example has three namespace 'tmpfs' types declared:
    ;    1) Global .tmpfs
    ;    2) file.tmpfs
    ;    3) other_ns.tmpfs
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

    ; This type is the global tmpfs:
    (type tmpfs)

    (block file
        ; file namespace tmpfs
        (type tmpfs)
        (class file (open read write getattr))

        ; This rule will reference the local namespace for src and tgt:
        (allow tmpfs tmpfs (file (open)))
        ; Resulting policy rule:
        ; allow file.tmpfs file.tmpfs : file.file open;

        ; This rule will reference the local namespace for src and global for tgt:
        (allow tmpfs .tmpfs (file (read)))
        ; Resulting policy rule:
        ; allow file.tmpfs tmpfs : file.file read;

        ; This rule will reference the global namespace for src and tgt:
        (allow .tmpfs .tmpfs (file (write)))
        ; Resulting policy rule:
        ; allow tmpfs tmpfs : file.file write;

        ; This rule will reference the other_ns namespace for src and
        ; local namespace for tgt:
        (allow other_ns.tmpfs tmpfs (file (getattr)))
        ; Resulting policy rule:
        ; allow other_ns.tmpfs file.tmpfs : file.file getattr;
    )

    (block other_ns
        (type tmpfs)
    )
```

Should the symbol not be prefixed with a dot, the current namespace would be searched first and then the global namespace (provided there is not a symbol of that name in the current namespace).

Expressions
-----------

Expressions may occur in the following CIL statements: [`booleanif`](cil_conditional_statements.md#booleanif), [`tunableif`](cil_conditional_statements.md#tunableif), [`classpermissionset`](cil_class_and_permission_statements.md#classpermissionset), [`typeattributeset`](cil_type_statements.md#typeattributeset), [`roleattributeset`](cil_role_statements.md#roleattributeset), [`categoryset`](cil_mls_labeling_statements.md#categoryset), [`constrain`](cil_constraint_statements.md#constrain), [`mlsconstrain`](cil_constraint_statements.md#mlsconstrain), [`validatetrans`](cil_constraint_statements.md#validatetrans), [`mlsvalidatetrans`](cil_constraint_statements.md#mlsvalidatetrans)

CIL expressions use the [prefix](http://www.cs.man.ac.uk/~pjj/cs212/fix.html) or Polish notation and may be nested (note that the kernel policy language uses infix notation). The syntax is as follows, where the parenthesis are part of the syntax:

```
    expr_set = (name ... | expr ...)
    expr = (expr_key expr_set ...)
    expr_key = and | or | xor | not | all | eq | neq | dom | domby | incomp | range
```

The number of `expr_set`'s in an `expr` is dependent on the statement type (there are four different classes as defined below) that also influence the valid `expr_key` entries (e.g. `dom`, `domby`, `incomp` are only allowed in constraint statements).

| expr_key | classpermissionset roleattributeset typeattributeset | categoryset | booleanif tunableif | constrain mlsconstrain validatetrans mlsvalidatetrans |
|:----------:|:----------:|:----------:|:----------:|:----------:|
| **`dom`**    |                        |                      |                      | **X**           |
| **`domby`**  |                        |                      |                      | **X**           |
| **`incomp`** |                        |                      |                      | **X**           |
| **`eq`**     |                        |                      | **X**                | **X**           |
| **`ne`**     |                        |                      | **X**                | **X**           |
| **`and`**    | **X**                  | **X**                | **X**                | **X**           |
| **`or`**     | **X**                  | **X**                | **X**                | **X**           |
| **`not`**    | **X**                  | **X**                | **X**                | **X**           |
| **`xor`**    | **X**                  | **X**                | **X**                |                 |
| **`all`**    | **X**                  | **X**                |                      |                 |
| **`range`**  |                        | **X**                |                      |                 |

1.  The [`classpermissionset`](cil_class_and_permission_statements.md#classpermissionset), [`roleattributeset`](cil_role_statements.md#roleattributeset) and [`typeattributeset`](cil_type_statements.md#typeattributeset) statements allow `expr_set` to mix names and `expr`s with `expr_key` values of: `and`, `or`, `xor`, `not`, `all` as shown in the examples:

    This example includes all `fs_type type` entries except `file.usermodehelper` and `file.proc_security` in the associated [`typeattribute`](cil_type_statements.md#typeattribute) identifier `all_fs_type_except_usermodehelper_and_proc_security`:

    ```secil
        (typeattribute all_fs_type_except_usermodehelper_and_proc_security)

        (typeattributeset all_fs_type_except_usermodehelper_and_proc_security
            (and
                (and
                    fs_type
                    (not file.usermodehelper)
                )
                (not file.proc_security)
            )
        )
    ```

    The `cps_1 classpermissionset` identifier includes all permissions except `load_policy` and `setenforce`:

    ```secil
        (class security (compute_av compute_create compute_member check_context load_policy compute_relabel compute_user setenforce setbool setsecparam setcheckreqprot read_policy))

        (classpermission cps_1)

        (classpermissionset cps_1 (security (not (load_policy setenforce))))
    ```

    This example includes all permissions in the associated [`classpermissionset`](cil_class_and_permission_statements.md#classpermissionset) identifier `security_all_perms`:

    ```secil
        (class security (compute_av compute_create compute_member check_context load_policy
            compute_relabel compute_user setenforce setbool setsecparam setcheckreqprot
            read_policy)
        )

        (classpermission security_all_perms)

        (classpermissionset security_all_perms (security (all)))
    ```

2.  The [`categoryset`](cil_mls_labeling_statements.md#categoryset) statement allows `expr_set` to mix names and `expr_key` values of: `and`, `or`, `not`, `xor`, `all`, `range` as shown in the examples.

    Category expressions are also allowed in [`sensitivitycategory`](cil_mls_labeling_statements.md#sensitivitycategory), [`level`](cil_mls_labeling_statements.md#level), and [`levelrange`](cil_mls_labeling_statements.md#levelrange) statements.

3.  The [`booleanif`](cil_conditional_statements.md#booleanif) and [`tunableif`](cil_conditional_statements.md#tunableif) statements only allow an `expr_set` to have one `name` or `expr` with `expr_key` values of `and`, `or`, `xor`, `not`, `eq`, `neq` as shown in the examples:

    ```secil
        (booleanif disableAudio
            (false
                (allow process device.audio_device (chr_file_set (rw_file_perms)))
            )
        )

        (booleanif (and (not disableAudio) (not disableAudioCapture))
            (true
                (allow process device.audio_capture_device (chr_file_set (rw_file_perms)))
            )
        )
    ```

4.  The [`constrain`](cil_constraint_statements.md#constrain), [`mlsconstrain`](cil_constraint_statements.md#mlsconstrain), [`validatetrans`](cil_constraint_statements.md#validatetrans) and [`mlsvalidatetrans`](cil_constraint_statements.md#mlsvalidatetrans) statements only allow an `expr_set` to have one `name` or `expr` with `expr_key` values of `and`, `or`, `not`, `all`, `eq`, `neq`, `dom`, `domby`, `incomp`. When `expr_key` is `dom`, `domby` or `incomp`, it must be followed by a string (e.g. `h1`, `l2`) and another string or a set of `name`s. The following examples show CIL constraint statements and their policy language equivalents:

    ```secil
        ; Process transition:  Require equivalence unless the subject is trusted.
        (mlsconstrain (process (transition dyntransition))
            (or (and (eq h1 h2) (eq l1 l2)) (eq t1 mlstrustedsubject)))

        ; The equivalent policy language mlsconstrain statememt is:
        ;mlsconstrain process { transition dyntransition }
        ;    ((h1 eq h2 and l1 eq l2) or t1 == mlstrustedsubject);

        ; Process read operations: No read up unless trusted.
        (mlsconstrain (process (getsched getsession getpgid getcap getattr ptrace share))
            (or (dom l1 l2) (eq t1 mlstrustedsubject)))

        ; The equivalent policy language mlsconstrain statememt is:
        ;mlsconstrain process { getsched getsession getpgid getcap getattr ptrace share }
        ;    (l1 dom l2 or t1 == mlstrustedsubject);
    ```

Name String
-----------

Used to define [`macro`](cil_call_macro_statements.md#macro) statement parameter string types:

```secil
    (call macro1("__kmsg__"))

    (macro macro1 ((string ARG1))
        (typetransition audit.process device.device chr_file ARG1 device.klog_device)
    )
```

Alternatively:

```secil
    (call macro1("__kmsg__"))

    (macro macro1 ((name ARG1))
        (typetransition audit.process device.device chr_file ARG1 device.klog_device)
    )
```

self
----

The [`self`](cil_reference_guide.md#self) keyword may be used as the target in AVC rule statements, and means that the target is the same as the source as shown in the following example:.

```secil
    (allow unconfined.process self (file (read write)))
```
