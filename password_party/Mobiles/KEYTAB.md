# Centrify keytab departure review

Keytab-based departure is supported as a Kerberos-ticket workflow, rather than a keytab argument to `adleave`:

1. Obtain a ticket with `kinit -kt <keytab> <principal>` under the privileged identity that will run the leave operation.
2. Run `adleave` using those cached credentials.

Delinea publishes this sequence in its [agent deactivation playbook](https://docs.delinea.com/online-help/integrations/redhat/cloud-suite/agents-activation-playbook.htm). [Centrify's own automation](https://github.com/centrify/AWS-Automation/blob/master/centrifydc-adleave.service) uses `/usr/share/centrifydc/kerberos/bin/kinit -kt ... <principal>`, followed by `adleave -I -r`.

The [command reference](https://docs.delinea.com/online-help/server-suite/commandref/centrify-command-reference-2025.pdf), in the adleave section dated March 2022, documents `-I`/`--noprompt`: fail instead of requesting credentials if none are available. This establishes documented behavior by that date; it does not identify the first agent release implementing it. The [2022 release notes](https://docs.delinea.com/online-help/server-suite/release-notes/auth/2022.htm) identify that product generation as 5.9.0. Neither source establishes 5.9.0 as a minimum version. No authoritative first-release statement was found. An installed agent version is still needed for a release-specific assessment; RHEL 7.9/8.10 alone does not identify the Centrify version.

`adleave -k` means **remove the system keytab**, not authenticate with a supplied keytab. `--remove` deletes the computer object; without it, the default leave deactivates it. Do not add either flag as a substitute for authenticating. These meanings are in the command reference above.

## Findings in the current implementation

- `New-LinuxTask-LeaveDomain` calls `dzdo kinit -k -t "$keytab"` without a principal. MIT documents that keytab authentication defaults to a local host principal; it does not simply select the user stored in that file. This is a concrete mismatch with a generated user keytab. See [MIT kinit](https://web.mit.edu/Kerberos/www/krb5-latest/doc/user/user_commands/kinit.html).
- The fragment uses the PATH-selected Kerberos binary, then invokes `adleave` through a separate `dzdo`. Use the installed Centrify Kerberos tools and verify both commands see the same privileged credential cache. The current code does not explicitly select a cache or destroy the obtained ticket afterward. The vendor examples demonstrate a single privileged execution context and clean up tickets afterward.
- `adleave` has no `--noprompt` in the current fragment, so missing usable credentials can result in a password prompt. Inspect the installed `adleave --help` before relying on `-I` for an older agent.
- `ktpass` generating a nonempty file is not proof of a usable AD credential. Confirm principal casing, current KVNO, and encryption compatibility through an actual `kinit`. [Microsoft's ktpass documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ktpass) specifically describes principal casing as significant. Redirecting `/pass *` input in the existing generator also remains unverified with the installed Windows tool.

These findings do not establish that the production agent lacks the feature. They identify issues to resolve in the current departure code and checks needed on the real agent. The Linux departure fragment has not been changed as part of this review.

## Identify the installed version

These commands inspect the target without leaving the domain:

```bash
adleave --version
adleave --help
rpm -q CentrifyDC
adinfo
```

The agent may have a different RPM package name after rebranding; `adleave --version` is the direct check. A successful ticket test below proves authentication, not permission to deactivate the computer or modify its Centrify zone.

## Test the keytab without leaving the domain

Run this interactively on a joined target with AD connectivity. Enter a root shell with `dzdo bash`; the remaining commands stay in that same shell. Substitute an existing protected keytab and the exact principal it contains. The temporary cache avoids replacing the shell's normal ticket cache.

```bash
work=$(mktemp -d) || exit 1
export KRB5CCNAME="FILE:$work/ccache"
/usr/share/centrifydc/kerberos/bin/kinit -kt /secure/path/leave.keytab 'account@REALM'
/usr/share/centrifydc/kerberos/bin/klist
/usr/share/centrifydc/kerberos/bin/kdestroy
unset KRB5CCNAME
rmdir "$work"
exit
```

Check that `kinit` succeeds and `klist` shows the intended account's TGT. Stop at this authentication test; it does not run `adleave` or modify domain membership. Successful authentication must still be followed by a representative, authorized leave test to establish AD/Centrify permissions and end-to-end behavior.

DC discovery for keytab generation now uses the controller's current AD domain. `-DomainController` has been removed from the CLI, registration function, and keytab resolver. A supplied keytab bypasses discovery and password prompting. This Windows-side discovery is separate from the Linux agent's own DC selection during the leave operation.
