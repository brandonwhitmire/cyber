+++
title = "IMAP/POP3"
+++

- `TCP 143/993`: IMAP unc/enc
- `TCP 110/995`: POP3 unc/enc

{{% details "Dangerous Settings" %}}

| **Setting**               | **Description**                                                                           |
| ------------------------- | ----------------------------------------------------------------------------------------- |
| `auth_debug`              | Enables all authentication debug logging.                                                 |
| `auth_debug_passwords`    | This setting adjusts log verbosity, the submitted passwords, and the scheme gets logged.  |
| `auth_verbose`            | Logs unsuccessful authentication attempts and their reasons.                              |
| `auth_verbose_passwords`  | Passwords used for authentication are logged and can also be truncated.                   |
| `auth_anonymous_username` | This specifies the username to be used when logging in with the ANONYMOUS SASL mechanism. |
{{% /details %}}

```bash
# Enumerate
sudo nmap -n -Pn -sV -sC -p25,110,143,465,587,993,995 <TARGET>

### Non-Interactive

# IMAPS
curl -vkL --user '<USER>':'<PASSWORD>' 'imaps://<TARGET>' -X <COMMAND>

# POP3S
curl -vkL --user '<USER>':'<PASSWORD>' 'pop3s://<TARGET>' -X <COMMAND>

### Interactive

# IMAPS
openssl s_client -connect <TARGET>:imaps
1 LOGIN <USERNAME> <PASSWORD>
1 LIST "" *	# Lists all directories
1 SELECT "<MAILBOX>" # Selects a mailbox
1 UNSELECT "<MAILBOX>" # Exits the selected mailbox
1 FETCH <ID> all # Metadata of email
1 FETCH 1:* (BODY[]) # Show all emails
1 CREATE "INBOX" # Creates a mailbox with a specified name
1 DELETE "INBOX" # Deletes a mailbox
1 RENAME "ToRead" "Important" #	Renames a mailbox
1 LSUB "" *	# Returns a subset of names from the set of names that the User has declared as being active or subscribed
1 CLOSE	# Removes all messages with the Deleted flag set
1 LOGOUT # Closes the connection

# POP3s
openssl s_client -connect <TARGET>:pop3s
USER <USERNAME>
PASS <PASSWORD>
STAT	# List num of saved emails from the server.
LIST	# List number and size of all emails.
RETR <ID>	# Deliver the requested email by ID.
DELE <ID> # Delete the requested email by ID.
CAPA	# Display the server capabilities.
RSET	# Reset the transmitted information.
QUIT	# Close connection
```
