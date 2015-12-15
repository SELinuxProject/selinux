Multi-Level Security Labeling Statements
========================================

Because there are many options for MLS labeling, the examples show a limited selection of statements, however there is a simple policy that will build shown in the [`levelrange`](cil_mls_labeling_statements.md#levelrange) section.

sensitivity
-----------

Declare a sensitivity identifier in the current namespace. Multiple [`sensitivity`](cil_mls_labeling_statements.md#sensitivity) statements in the policy will form an ordered list.

**Statement definition:**

    (sensitivity sensitivity_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>sensitivity</code></p></td>
<td align="left"><p>The <code>sensitivity</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>sensitivity_id</code></p></td>
<td align="left"><p>The <code>sensitivity</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example declares three [`sensitivity`](cil_mls_labeling_statements.md#sensitivity) identifiers:

    (sensitivity s0)
    (sensitivity s1)
    (sensitivity s2)

sensitivityalias
----------------

Declares a sensitivity alias identifier in the current namespace. See the [`sensitivityaliasactual`](cil_mls_labeling_statements.md#sensitivityaliasactual) statement for an example that associates the [`sensitivityalias`](cil_mls_labeling_statements.md#sensitivityalias) identifier.

**Statement definition:**

    (sensitivityalias sensitivityalias_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>sensitivityalias</code></p></td>
<td align="left"><p>The <code>sensitivityalias</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>sensitivityalias_id</code></p></td>
<td align="left"><p>The <code>sensitivityalias</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Example:**

See the [`sensitivityaliasactual`](cil_mls_labeling_statements.md#sensitivityaliasactual) statement.

sensitivityaliasactual
----------------------

Associates a previously declared [`sensitivityalias`](cil_mls_labeling_statements.md#sensitivityalias) identifier to a previously declared [`sensitivity`](cil_mls_labeling_statements.md#sensitivity) identifier.

**Statement definition:**

    (sensitivityaliasactual sensitivityalias_id sensitivity_id)

**Where:**

<table>
<colgroup>
<col width="29%" />
<col width="70%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>sensitivityaliasactual</code></p></td>
<td align="left"><p>The <code>sensitivityaliasactual</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>sensitivityalias_id</code></p></td>
<td align="left"><p>A single previously declared <code>sensitivityalias</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>sensitivity_id</code></p></td>
<td align="left"><p>A single previously declared <code>sensitivity</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example will associate sensitivity `s0` with two sensitivity alias's:

    (sensitivity s0)
    (sensitivityalias unclassified)
    (sensitivityalias SystemLow)
    (sensitivityaliasactual unclassified s0)
    (sensitivityaliasactual SystemLow s0)

sensitivityorder
----------------

Define the sensitivity order - lowest to highest. Multiple [`sensitivityorder`](cil_mls_labeling_statements.md#sensitivityorder) statements in the policy will form an ordered list.

**Statement definition:**

    (sensitivityorder (sensitivity_id ...))

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>sensitivityorder</code></p></td>
<td align="left"><p>The <code>sensitivityorder</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>sensitivity_id</code></p></td>
<td align="left"><p>One or more previously declared <code>sensitivity</code> or <code>sensitivityalias</code> identifiers..</p></td>
</tr>
</tbody>
</table>

**Example:**

This example shows two [`sensitivityorder`](cil_mls_labeling_statements.md#sensitivityorder) statements that when compiled will form an ordered list. Note however that the second [`sensitivityorder`](cil_mls_labeling_statements.md#sensitivityorder) statement starts with `s2` so that the ordered list can be built.

    (sensitivity s0)
    (sensitivityalias s0 SystemLow)
    (sensitivity s1)
    (sensitivity s2)
    (sensitivityorder (SystemLow s1 s2))

    (sensitivity s3)
    (sensitivity s4)
    (sensitivityalias s4 SystemHigh)
    (sensitivityorder (s2 s3 SystemHigh))

category
--------

Declare a category identifier in the current namespace. Multiple category statements declared in the policy will form an ordered list.

**Statement definition:**

    (category category_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>category</code></p></td>
<td align="left"><p>The <code>category</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>category_id</code></p></td>
<td align="left"><p>The <code>category</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example declares a three [`category`](cil_mls_labeling_statements.md#category) identifiers:

    (category c0)
    (category c1)
    (category c2)

categoryalias
-------------

Declares a category alias identifier in the current namespace. See the [`categoryaliasactual`](cil_mls_labeling_statements.md#categoryaliasactual) statement for an example that associates the [`categoryalias`](cil_mls_labeling_statements.md#categoryalias) identifier.

**Statement definition:**

    (categoryalias categoryalias_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>categoryalias</code></p></td>
<td align="left"><p>The <code>categoryalias</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>categoryalias_id</code></p></td>
<td align="left"><p>The <code>categoryalias</code> identifier.</p></td>
</tr>
</tbody>
</table>

categoryaliasactual
-------------------

Associates a previously declared [`categoryalias`](cil_mls_labeling_statements.md#categoryalias) identifier to a previously declared [`category`](cil_mls_labeling_statements.md#category) identifier.

**Statement definition:**

    (categoryaliasactual categoryalias_id category_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>categoryaliasactual</code></p></td>
<td align="left"><p>The <code>categoryaliasactual</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>categoryalias_id</code></p></td>
<td align="left"><p>A single previously declared <code>categoryalias</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>category_id</code></p></td>
<td align="left"><p>A single previously declared <code>category</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Example:**

Declares a category `c0`, a category alias of `documents`, and then associates them:

    (category c0)
    (categoryalias documents)
    (categoryaliasactual documents c0)

categoryorder
-------------

Define the category order. Multiple [`categoryorder`](cil_mls_labeling_statements.md#categoryorder) statements declared in the policy will form an ordered list. Note that this statement orders the categories to allow validation of category ranges.

**Statement definition:**

    (categoryorder (category_id ...))

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>categoryorder</code></p></td>
<td align="left"><p>The <code>categoryorder</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>category_id</code></p></td>
<td align="left"><p>One or more previously declared <code>category</code> or <code>categoryalias</code> identifiers.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example orders one category alias and nine categories:

    (categoryorder (documents c1 c2 c3 c4 c5 c6 c7 c8 c9)

categoryset
-----------

Declare an identifier for a set of contiguous or non-contiguous categories in the current namespace.

Notes:

-   Category expressions are allowed in [`categoryset`](cil_mls_labeling_statements.md#categoryset), [`sensitivitycategory`](cil_mls_labeling_statements.md#sensitivitycategory), [`level`](cil_mls_labeling_statements.md#level), and [`levelrange`](cil_mls_labeling_statements.md#levelrange) statements.

-   Category sets are not allowed in [`categoryorder`](cil_mls_labeling_statements.md#categoryorder) statements.

**Statement definition:**

    (categoryset categoryset_id (category_id ... | expr ...))

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>categoryset</code></p></td>
<td align="left"><p>The <code>categoryset</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>categoryset_id</code></p></td>
<td align="left"><p>The <code>categoryset</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>category_id</code></p></td>
<td align="left"><p>Zero or more previously declared <code>category</code> or <code>categoryalias</code> identifiers.</p>
<p>Note that there must be at least one <code>category_id</code> identifier or <code>expr</code> parameter declared.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>expr</code></p></td>
<td align="left"><p>Zero or more <code>expr</code>'s, the valid operators and syntax are:</p>
<p><code>    (and (category_id ...) (category_id ...))</code></p>
<p><code>    (or  (category_id ...) (category_id ...))</code></p>
<p><code>    (xor (category_id ...) (category_id ...))</code></p>
<p><code>    (not (category_id ...))</code></p>
<p><code>    (range category_id category_id)</code></p>
<p><code>    (all)</code></p></td>
</tr>
</tbody>
</table>

**Examples:**

These examples show a selection of [`categoryset`](cil_mls_labeling_statements.md#categoryset) statements:

    ; Declare categories with two alias's:
    (category c0)
    (categoryalias documents)
    (categoryaliasactual documents c0)
    (category c1)
    (category c2)
    (category c3)
    (category c4)
    (categoryalias spreadsheets)
    (categoryaliasactual spreadsheets c4)

    ; Set the order to determine ranges:
    (categoryorder (c0 c1 c2 c3 spreadsheets))

    (categoryset catrange_1 (range c2 c3))

    ; Two methods to associate all categories:
    (categoryset all_cats (range c0 c4))
    (categoryset all_cats1 (all))

    (categoryset catset_1 (documents c1))
    (categoryset catset_2 (c2 c3))
    (categoryset catset_3 (c4))

    (categoryset just_c0 (xor (c1 c2) (documents c1 c2)))

sensitivitycategory
-------------------

Associate a [`sensitivity`](cil_mls_labeling_statements.md#sensitivity) identifier with one or more [category](#category)'s. Multiple definitions for the same [`sensitivity`](cil_mls_labeling_statements.md#sensitivity) form an ordered list of categories for that sensitivity. This statement is required before a [`level`](cil_mls_labeling_statements.md#level) identifier can be declared.

**Statement definition:**

    (sensitivitycategory sensitivity_id categoryset_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>sensitivitycategory</code></p></td>
<td align="left"><p>The <code>sensitivitycategory</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>sensitivity_id</code></p></td>
<td align="left"><p>A single previously declared <code>sensitivity</code> or <code>sensitivityalias</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>categoryset_id</code></p></td>
<td align="left"><p>A single previously declared <code>categoryset</code> (named or anonymous), or a list of <code>category</code> and/or <code>categoryalias</code> identifiers. The examples show each variation.</p></td>
</tr>
</tbody>
</table>

**Examples:**

These [`sensitivitycategory`](cil_mls_labeling_statements.md#sensitivitycategory) examples use a selection of [`category`](cil_mls_labeling_statements.md#category), [`categoryalias`](cil_mls_labeling_statements.md#categoryalias) and [`categoryset`](cil_mls_labeling_statements.md#categoryset)'s:

    (sensitivitycategory s0 catrange_1)
    (sensitivitycategory s0 catset_1)
    (sensitivitycategory s0 catset_3)
    (sensitivitycategory s0 (all))
    (sensitivitycategory unclassified (range documents c2))

level
-----

Declare a [`level`](cil_mls_labeling_statements.md#level) identifier in the current namespace and associate it to a previously declared [`sensitivity`](cil_mls_labeling_statements.md#sensitivity) and zero or more categories. Note that if categories are required, then before this statement can be resolved the [`sensitivitycategory`](cil_mls_labeling_statements.md#sensitivitycategory) statement must be used to associate categories with the sensitivity.

**Statement definition:**

    level level_id (sensitivity_id [categoryset_id])

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>level</code></p></td>
<td align="left"><p>The <code>level</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>level_id</code></p></td>
<td align="left"><p>The <code>level</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>sensitivity_id</code></p></td>
<td align="left"><p>A single previously declared <code>sensitivity</code> or <code>sensitivityalias</code> identifier.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>categoryset_id</code></p></td>
<td align="left"><p>A single previously declared <code>categoryset</code> (named or anonymous), or a list of <code>category</code> and/or <code>categoryalias</code> identifiers. The examples show each variation.</p></td>
</tr>
</tbody>
</table>

**Examples:**

These [`level`](cil_mls_labeling_statements.md#level) examples use a selection of [`category`](cil_mls_labeling_statements.md#category), [`categoryalias`](cil_mls_labeling_statements.md#categoryalias) and [`categoryset`](cil_mls_labeling_statements.md#categoryset)'s:

    (level systemLow (s0))
    (level level_1 (s0))
    (level level_2 (s0 (catrange_1)))
    (level level_3 (s0 (all_cats)))
    (level level_4 (unclassified (c2 c3 c4)))

levelrange
----------

Declare a level range identifier in the current namespace and associate a current and clearance level.

**Statement definition:**

    (levelrange levelrange_id (low_level_id high_level_id))

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>levelrange</code></p></td>
<td align="left"><p>The <code>levelrange</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>levelrange_id</code></p></td>
<td align="left"><p>The <code>levelrange</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>low_level_id</code></p></td>
<td align="left"><p>The current level specified by a previously declared <code>level</code> identifier. This may be formed by named or anonymous components as discussed in the <code>level</code> section and shown in the examples.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>high_level_id</code></p></td>
<td align="left"><p>The clearance or high level specified by a previously declared <code>level</code> identifier. This may be formed by named or anonymous components as discussed in the <code>level</code> section and shown in the examples.</p></td>
</tr>
</tbody>
</table>

**Examples:**

This example policy shows [`levelrange`](cil_mls_labeling_statements.md#levelrange) statement and all the other MLS labeling statements discussed in this section and will compile as a standalone policy:

    (handleunknown allow)
    (mls true)

    ; There must be least one set of SID statements in a policy:
    (sid kernel)
    (sidorder (kernel))
    (sidcontext kernel unconfined.context_1)

    (sensitivitycategory s0 (c4 c2 c3 c1 c0 c3))

    (category c0)
    (categoryalias documents)
    (categoryaliasactual documents c0)
    (category c1)
    (category c2)
    (category c3)
    (category c4)
    (categoryalias spreadsheets)
    (categoryaliasactual spreadsheets c4)

    (categoryorder (c0 c1 c2 c3 spreadsheets))

    (categoryset catrange_1 (range c2 c3))
    (categoryset all_cats (range c0 c4))
    (categoryset all_cats1 (all))

    (categoryset catset_1 (documents c1))
    (categoryset catset_2 (c2 c3))
    (categoryset catset_3 (c4))

    (categoryset just_c0 (xor (c1 c2) (documents c1 c2)))

    (sensitivity s0)
    (sensitivityalias unclassified)
    (sensitivityaliasactual unclassified s0)

    (sensitivityorder (s0))
    (sensitivitycategory s0 (c0))

    (sensitivitycategory s0 catrange_1)
    (sensitivitycategory s0 catset_1)
    (sensitivitycategory s0 catset_3)
    (sensitivitycategory s0 (all))
    (sensitivitycategory s0 (range documents c2))

    (level systemLow (s0))
    (level level_1 (s0))
    (level level_2 (s0 (catrange_1)))
    (level level_3 (s0 (all_cats)))
    (level level_4 (unclassified (c2 c3 c4)))

    (levelrange levelrange_2 (level_2 level_2))
    (levelrange levelrange_1 ((s0) level_2))
    (levelrange low_low (systemLow systemLow))

    (context context_2 (unconfined.user object_r unconfined.object (level_1 level_3)))

    ; Define object_r role. This must be assigned in CIL.
    (role object_r)

    (block unconfined
        (user user)
        (role role)
        (type process)
        (type object)
        (userrange user (systemLow systemLow))
        (userlevel user systemLow)
        (userrole user role)
        (userrole user object_r)
        (roletype role process)
        (roletype role object)
        (roletype object_r object)

        (class file (open execute read write))

        ; There must be least one allow rule in a policy:
        (allow process self (file (read)))

        (context context_1 (user object_r object low_low))
    ) ; End unconfined namespace

rangetransition
---------------

Allows an objects level to transition to a different level. Generally used to ensure processes run with their correct MLS range, for example `init` would run at `SystemHigh` and needs to initialise / run other processes at their correct MLS range.

**Statement definition:**

    (rangetransition source_id target_id class_id new_range_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>rangetransition</code></p></td>
<td align="left"><p>The <code>rangetransition</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>source_type_id</code></p></td>
<td align="left"><p>A single previously declared <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>target_type_id</code></p></td>
<td align="left"><p>A single previously declared <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>class_id</code></p></td>
<td align="left"><p>A single previously declared <code>class</code> or <code>classmap</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>new_range_id</code></p></td>
<td align="left"><p>The new MLS range for the object class that is a previously declared <code>levelrange</code> identifier. This entry may also be defined as an anonymous or named <code>level</code>, <code>sensitivity</code>, <code>sensitivityalias</code>, <code>category</code>, <code>categoryalias</code> or <code>categoryset</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Examples:**

This rule will transition the range of `sshd.exec` to `s0 - s1:c0.c3` on execution from the `init.process`:

    (sensitivity s0)
    (sensitivity s1)
    (sensitivityorder s0 s1)
    (category c0)
    ...
    (level systemlow (s0)
    (level systemhigh (s1 (c0 c1 c2)))
    (levelrange low_high (systemlow systemhigh))

    (rangetransition init.process sshd.exec process low_high)
