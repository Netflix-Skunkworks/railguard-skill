<!-- CANARY:RGS:rule:sql-injection -->

# SQL Injection Prevention Security Rules

## R: Risk First

**Goal**: Prevent SQL injection attacks that allow unauthorized database access and manipulation
**Risk**: Data breach, unauthorized data access, data modification/deletion, authentication bypass, and complete database compromise
**Context**: Applications using SQL databases including MySQL, PostgreSQL, SQL Server, Oracle, SQLite, and any SQL-based data storage

## A: Attached Constraints

**CRITICAL SECURITY BOUNDARIES**:
- ALWAYS use parameterized queries (prepared statements) for all SQL operations
- NEVER concatenate user input directly into SQL query strings
- ALWAYS validate and sanitize all input before database operations
- NEVER use dynamic SQL generation with user input unless absolutely necessary
- ALWAYS implement least privilege database access controls
- NEVER grant excessive database permissions to application accounts
- ALWAYS use allowlist input validation for table names, column names, and sort parameters
- NEVER trust any user-supplied input in SQL contexts without proper validation

**SECURITY AWARENESS**:
- SQL injection is one of the most common and dangerous web application vulnerabilities
- String concatenation with user input is the primary cause of SQL injection vulnerabilities
- Prepared statements provide the strongest defense against SQL injection attacks
- Input validation alone is insufficient - parameterized queries are essential

## I: Interpretative Framing

**When building database queries**:
- Use prepared statements with parameter binding for all user input
- Implement proper input validation as a secondary defense layer
- Apply least privilege principles to database account permissions
- Use stored procedures only when implemented with proper parameterization

**When handling dynamic query requirements**:
- Use allowlist validation for table names, column names, and sort order parameters
- Convert user input to non-string types (boolean, numeric) when possible before query construction
- Implement query redesign to avoid dynamic SQL generation with user input
- Use database views to limit data access granularity

**When implementing database access controls**:
- Create separate database accounts for different application functions
- Grant minimum necessary permissions (read-only where possible)
- Use database views to restrict access to specific fields or joined tables
- Implement proper error handling that doesn't expose database structure

**When reviewing existing database code**:
- Identify all locations where user input reaches SQL queries
- Flag any string concatenation or interpolation in SQL query construction
- Verify that all database operations use parameterized queries
- Check database account permissions and privilege levels

## L: Local Defaults

### Prepared Statement Requirements

**Parameterized Query Implementation:**
Use prepared statements with parameter binding for all SQL operations. The database must distinguish between SQL code and user data regardless of input content. Parameters should be bound using proper data type specifications.

**Query Structure Separation:**
Define all SQL code structure first, then pass user input as parameters. Never allow user input to modify the fundamental structure or logic of SQL queries. Use placeholder markers (?, :param, @param) for all user-supplied values.

**Input Type Validation:**
Validate and convert user input to appropriate data types before parameter binding. Use strict type checking for numeric, date, boolean, and enumerated values. Implement length limits and format validation for string parameters.

### Dynamic Query Restrictions

**Table and Column Name Handling:**
When table names, column names, or sort parameters must be dynamic, use allowlist validation with predefined acceptable values. Map user parameters to known safe database identifiers. Never directly concatenate user input into table or column name positions.

**Sort Order and Filtering:**
Convert user input for sort order to boolean values, then use conditional logic to select safe ASC/DESC values. For filtering parameters, use allowlist validation against known acceptable filter criteria. Implement query redesign to avoid dynamic WHERE clause construction.

**Stored Procedure Safety:**
When using stored procedures, ensure they use parameterized inputs and do not perform dynamic SQL generation internally. Avoid stored procedures that use EXECUTE, EXEC, or sp_execute commands with user input. Implement proper parameter validation within stored procedures.

### Database Access Control

**Least Privilege Implementation:**
Create dedicated database accounts for each application function with minimum necessary permissions. Use read-only accounts for operations that only require data retrieval. Separate accounts for different security contexts (public access, authenticated users, administrative functions).

**Permission Granularity:**
Grant table-level permissions only where necessary, prefer view-based access for restricted data exposure. Avoid granting CREATE, DROP, ALTER, or administrative permissions to application accounts. Use database roles to manage permission sets consistently.

**Connection Security:**
Use encrypted connections (TLS/SSL) for all database communications. Implement connection pooling with proper authentication and session management. Store database credentials securely using environment variables or secure credential management systems.

### Input Validation Layers

**Primary Validation:**
Implement comprehensive input validation before any database operations. Use allowlist validation for all user inputs that will be used in SQL contexts. Validate data types, lengths, formats, and acceptable value ranges.

**Secondary Validation:**
Apply additional validation within database operations using CHECK constraints and triggers where appropriate. Implement business logic validation to ensure data integrity beyond basic format checking. Use database-level constraints to enforce data consistency.

**Error Handling:**
Implement secure error handling that logs security events without exposing database structure or sensitive information to users. Use generic error messages for user-facing responses while maintaining detailed logging for security analysis.

### Vulnerability Detection Patterns

**High-Risk Code Patterns:**
Flag any SQL query construction using string concatenation, interpolation, or formatting with user input. Identify dynamic SQL generation in stored procedures or application code. Detect missing parameterization in ORM queries or raw SQL operations.

**Database Permission Auditing:**
Review database account permissions for excessive privileges (DBA, db_owner, administrative roles). Identify accounts with unnecessary CREATE, DROP, or ALTER permissions. Check for shared database accounts across different application functions.

**Input Flow Analysis:**
Trace user input from entry points to database operations to identify unvalidated paths. Verify that all user input undergoes proper validation and parameterization before reaching SQL queries. Check for indirect SQL injection through stored data or configuration files.

## G: Generative Path Checks

1. **SQL Database Detection**: Are SQL databases (MySQL, PostgreSQL, SQL Server, Oracle, SQLite) used in the application?
2. **Query Construction**: Are SQL queries constructed using parameterized statements rather than string concatenation?
3. **User Input Handling**: Is all user input properly validated and parameterized before database operations?
4. **Dynamic Query Analysis**: Are dynamic table names, column names, or sort parameters handled with allowlist validation?
5. **Database Permissions**: Are database accounts configured with least privilege access controls?
6. **Stored Procedure Safety**: Are stored procedures implemented without dynamic SQL generation using user input?
7. **Input Validation**: Is comprehensive input validation implemented as a secondary defense layer?
8. **Error Handling**: Are database errors handled securely without exposing sensitive information?
9. **Connection Security**: Are database connections encrypted and properly authenticated?
10. **Code Review Coverage**: Have all database interaction points been reviewed for SQL injection vulnerabilities?

## U: Uncertainty Disclosure

**When uncertain about SQL injection prevention requirements**:
- Default to using parameterized queries for all database operations
- Implement the most restrictive input validation possible
- Use least privilege database access controls
- Apply comprehensive logging for all database security events
- Consult with database security specialists for complex scenarios

**When database integration requirements are unclear**:
- Assume all user input could be malicious and requires parameterization
- Treat all dynamic query requirements as high-risk and requiring allowlist validation
- Implement defense-in-depth with multiple validation layers
- Use established ORM frameworks with built-in SQL injection protection
- Apply database-level security controls as additional protection layers

## A: Auditability

**Required Security Comments**:
- SECURITY: Mark all database query construction with security comments explaining parameterization
- SQL_INJECTION: Document input validation and parameterization logic for all user inputs
- DATABASE: Document database permission models and access control implementations
- VALIDATION: Document input validation rules and allowlist implementations

**Logging Requirements**:
- Log all SQL injection attempt detections with input patterns and source information
- Monitor database access patterns for unusual queries or permission escalation attempts
- Track parameterized query usage and flag any dynamic SQL generation
- Include timestamp, user context, and query patterns in security logs
- Never log actual SQL query content or sensitive data in security logs

## R+D: Revision + Dialogue

**Security Review Questions**:
- "Are all SQL queries using parameterized statements with proper parameter binding?"
- "Is user input properly validated and sanitized before any database operations?"
- "Are database accounts configured with least privilege access controls?"
- "Do we have proper input validation for dynamic table names, column names, and sort parameters?"
- "Are stored procedures implemented without dynamic SQL generation using user input?"
- "Is comprehensive error handling in place that doesn't expose database structure?"
- "Are database connections encrypted and properly authenticated?"
- "Have we reviewed all code paths where user input reaches database operations?"

**Core Security Principle**:
Never trust user input in SQL contexts. Always use parameterized queries with proper parameter binding, implement comprehensive input validation as a secondary defense, and apply least privilege database access controls to minimize the impact of successful attacks and prevent SQL injection vulnerabilities.
