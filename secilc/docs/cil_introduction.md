Introduction
===================

The SELinux Common Intermediate Language (CIL) is designed to be a language that sits between one or more high level policy languages (such as the current module language) and the low-level kernel policy representation. The intermediate language provides several benefits:

* Enables the creation of multiple high-level languages that can both consume and produce language constructs with more features than the raw kernel policy (e.g., interfaces). Pushing these features into CIL enables cross-language interaction.

* Eases the creation of high-level languages, encouraging the creation of more domain specific policy languages (e.g., CDS Framework, Lobster, and Shrimp).

* Provides a semantically rich representation suitable for policy analysis, allowing the analysis of the output of multiple high-level languages using a single analysis tool set without losing needed high-level information.

Design Philosophy
------------------

CIL is guided by several key decision principles:

* Be an intermediate language - provide rich semantics needed for cross-language interaction but not for convenience. If a feature can be handled by a high-level language without sacrificing cross-language interoperability leave the feature out. Less is more.

* Facilitate easy parsing and generation - provide clear, simple syntax that is easy to parse and to generate by high-level compilers, analysis tools, and policy generation tools. Machine processing should be prioritized higher than human processing when there is a conflict as humans should be reading and writing high-level languages instead.

* Fully and faithfully represent the kernel language - the ultimate goal of CIL is the generation of the policy that will be enforced by the kernel. That policy must be full represented so that all of the policy can be represented in CIL. And that representation should not adorn, obscure, or otherwise hide the kernel policy. CIL should allow additional high-level language semantics but should not abstract away the essence of the kernel enforcement. Be C (portable assembler) not a pure functional language (which hides how the processor actually works).

* The only good binary file format is a non-existent one - CIL is meant for a source policy oriented world, so assume and leverage that. The only binary policy format moving forward should be for communication with the kernel.

* Enable backwards compatibility but don't be a slave to it - source, but not binary, compatibility with existing policies is a goal but not an absolute requirement. Where necessary it is assumed that manual or automated policy conversion will be required to move to enable the freedom needed to make CIL compelling.

* Don't fix what isn't broken - CIL is an opportunity to make bold changes to SELinux policy, but there is no reason to re-think core concepts that are working well. All changes to existing language constructs need a clear and compelling reason. One key aspect of the current policy to retain is it's order-independent, declarative style.

* No more M4 - the pervasive use of M4 and pre-processing in general has eased policy creation, but the side-effects cause many additional problems. CIL should eliminate the need for a pre-processor.

* Shift more compilation work to happen per-module instead of globally - the current toolchain performance is often driven by the size of the policy and the need to have the entire policy loaded to do much of the processing. If possible, make it possible to do more compilation of one module at a time to increase performance. At the very least, clearly identify and manage language constructs that cause work on the global policy.

Goals and Primary Features
-----

CIL is meant to enable several features that are currently difficult or impossible to achieve with the current policy languages and tools. While generality is always a goal, with CIL there are also several well-known and clear motivating language needs.

* Policy customization without breaking updates - one of the challenges in SELinux is allowing a system builder or administrator to change the access allowed on a system - including removing unwanted access - while not preventing the application of future policy updates from the vendor. It is desirable, therefore, to allow an administrator to make changes to vendor policy without necessitating the direct modification of the shipped policy files. This is most clearly seen when an administrator wants to remove access allowed by a vendor policy that is not already controlled by a policy boolean.

* Interfaces as a first class feature - interfaces, and macros before them, have been a successful mechanism to allow policy authors to define related sets of access and easily grant that access to new types. However, this success has been hampered by interfaces existing solely as pre-processor constructs, preventing compilers, management tools, and analysis tools from understanding them. This has many unintended consequences, including the need to recompile all modules to include the changes to an interface. Interfaces or some similar construct should become first class language features.

* Rich policy relationships - templates, interfaces, and attributes are currently the only means of quickly creating new types or sets of types with commonly needed access. However, use of these constructs require up-front design by the policy developer, limiting their use by system builders and administrators to rapidly create or mold existing policy. Policy authors need language features to create new types or modules based upon existing ones with large or small changes. These features should allow ad-hoc creation of new policy modules or types related to existing types.

* Support for policy management - semanage and related tools currently make policy modifications using private data stores and code to directly manipulate the binary policy format before it is generated for loading into the kernel. These tools should be able to generate and consume CIL to accomplish the same goals.

Design Overview
------------------

The design is aims to provide simplicity in several ways:

1. The syntax is extremely regular and easy to parse being based upon s-expressions.
2. The statements are reduced to the bare minimum. There is one - and only one - way to express any given syntax.
3. The statements are unambiguous and overlap in very well defined ways. This is in contrast to the current language where a statement, such as a role statement, might be a declaration, a further definition, or both depending on context.

The language, like the existing policy languages, is declarative. It removes all of the ordering constraints from the previous languages. Finally, the language is meant to be processed in source form as a single compilation unit - there is no module-by-module compilation. This has advantages (no need for compiled disk representation, better error reporting, simpler processing) with the primary disadvantage of space. However, this is not a problem in practice as the linking process for the binary policy modules required the entire representation in memory as well. It is, in many ways, a natural result of the declarative nature of the language.

In many ways, this design document describes what is different between the current language and CIL. For example, types have exactly the same semantics as they currently do, CIL simply uses a different syntax for declaring and referencing them. Consequently, no space is spent describing the semantics of types and only a small amount of space spent discussing the new syntax separate from interaction with new CIL features. Contrastingly, CIL has new constructs for creating, managing, and traversing namespace. There is a corresponding amount of space describing the semantics of those features.

When referring to current semantics it is important to note that there are currently three separate policy languages in common usage: the reference policy syntax created in M4 (which includes interfaces and templates), the module syntax understood by checkmodule, and what is commonly called the kernel policy which is the policy understood by checkpolicy. In general, CIL preserves the current kernel policy almost unchanged (just with different syntax) and layers on features from the module language, reference policy, and novel new features. When discussing current semantics, if the context is not clear attempts will be made to clarify which policy language is being referenced.
