<!-- CANARY:RGS:rule:logic-vulnerabilities -->

# Logic Vulnerability Analysis Security Rules

## R: Risk First

**Goal**: Identify and prevent business logic flaws and design vulnerabilities that cannot be addressed through input validation
**Risk**: Unauthorized access, privilege escalation, financial fraud, data manipulation, workflow bypass, and complete business process compromise
**Context**: Applications with complex business logic, multi-step workflows, state management, financial transactions, and cross-system integrations

## A: Attached Constraints

**CRITICAL SECURITY BOUNDARIES**:
- ALWAYS validate business rule enforcement across all code paths and API endpoints
- NEVER trust client-supplied business logic parameters or state information
- ALWAYS implement proper state validation and transition controls in workflows
- NEVER allow workflow step skipping or state reordering without proper authorization
- ALWAYS enforce object ownership and tenant isolation at the data access layer
- NEVER rely solely on client-side validation for business rule enforcement
- ALWAYS implement atomic operations for critical business transactions
- NEVER trust external system responses without proper verification and validation

**SECURITY AWARENESS**:
- Logic vulnerabilities exploit intended functionality rather than implementation flaws
- These vulnerabilities often span multiple requests, sessions, or services
- Business logic flaws are difficult to detect with traditional static analysis tools
- State management and workflow logic are common sources of logic vulnerabilities
- Cross-system integrations and trust boundaries are high-risk areas for logic flaws

## I: Interpretative Framing

**When analyzing applications with complex business logic**:
- Map all business processes, workflows, and state transitions for potential bypass opportunities
- Identify trust boundaries between systems, services, and user contexts
- Analyze cross-request dependencies and multi-step process flows
- Review financial calculations, pricing logic, and economic transaction handling

**When reviewing authentication and authorization logic**:
- Verify object ownership validation beyond basic authentication checks
- Analyze privilege escalation paths through legitimate application features
- Review session management and authentication state transitions
- Examine multi-factor authentication and step-up authentication workflows

**When assessing workflow and state management**:
- Validate that all workflow steps verify prerequisite states and conditions
- Ensure state transitions are properly controlled and cannot be manipulated
- Review approval processes and administrative workflow bypass opportunities
- Analyze concurrent operations and race condition possibilities

**When evaluating integration and trust boundaries**:
- Verify proper validation of external system responses and webhooks
- Review federated authentication and token handling logic
- Analyze payment processing and financial integration trust assumptions
- Examine service-to-service communication security and validation

## L: Local Defaults

### Authorization and Access Control Validation

**Object Ownership Verification:**
Implement comprehensive object-level authorization that validates user ownership or access rights for every resource access. Bind all data access operations to authenticated user context and tenant scope. Use consistent authorization patterns across all API endpoints and avoid relying on client-supplied object identifiers without server-side validation.

**Cross-Tenant Isolation Enforcement:**
Ensure multi-tenant applications properly isolate tenant data through server-side validation rather than client-supplied tenant identifiers. Implement tenant context binding at the database query level and validate tenant scope for all data operations. Use tenant-aware data access patterns and avoid global object identifiers that could leak across tenant boundaries.

**Privilege Escalation Prevention:**
Review all application features that could be combined or abused for privilege escalation. Implement proper role validation for administrative functions and avoid role inheritance flaws. Use principle of least privilege for all operations and implement step-up authentication for high-risk actions.

### Workflow and State Management Security

**State Transition Validation:**
Implement proper state machine validation that verifies current state before allowing transitions. Ensure all workflow steps validate prerequisite conditions and cannot be bypassed through direct endpoint access. Use atomic state updates and implement proper concurrency controls for state modifications.

**Business Process Integrity:**
Validate that multi-step business processes enforce proper sequencing and cannot be reordered or skipped. Implement comprehensive prerequisite checking for finalization operations like payment processing, order fulfillment, or account activation. Use workflow tokens or state validation to prevent step bypass attacks.

**Approval Workflow Security:**
Ensure approval processes cannot be bypassed through state manipulation, role confusion, or timing attacks. Implement proper audit trails for all approval actions and validate approver authority for each approval operation. Use separation of duties principles and avoid self-approval scenarios.

### Temporal and Concurrency Security

**Race Condition Prevention:**
Implement atomic operations for all critical business transactions that involve resource allocation, financial calculations, or state modifications. Use proper database transaction isolation levels and implement optimistic or pessimistic locking for concurrent operations. Validate resource availability at the time of consumption rather than just at check time.

**Idempotency Implementation:**
Ensure all critical operations are idempotent and cannot be replayed for additional effects. Implement proper request deduplication using idempotency keys or nonce validation. Use unique transaction identifiers and validate against duplicate processing for financial operations and state changes.

**Time-Based Security Controls:**
Implement proper expiration handling for tokens, sessions, and time-sensitive operations. Use server-side time validation and avoid client-supplied timestamps for security decisions. Implement proper clock synchronization and handle timezone differences consistently across distributed systems.

### Integration and Trust Boundary Security

**External System Validation:**
Never trust external system responses without proper verification and validation. Implement cryptographic verification for webhooks and callbacks from payment processors, identity providers, and other external services. Use proper request signing and validate all parameters in external system communications.

**Federated Authentication Security:**
Implement comprehensive validation for OAuth, SAML, and other federated authentication flows. Validate redirect URIs, state parameters, and token audience claims. Implement proper token binding and avoid token confusion between different applications or contexts.

**Service Communication Security:**
Ensure service-to-service communications implement proper authentication and authorization. Avoid implicit trust between internal services and implement proper service identity validation. Use mutual TLS or equivalent mechanisms for service authentication and validate service permissions for each operation.

### Financial and Economic Logic Security

**Transaction Integrity:**
Implement proper validation for all financial calculations including taxes, discounts, currency conversions, and fee calculations. Use appropriate precision for monetary calculations and implement proper rounding logic. Validate transaction amounts and prevent manipulation through parameter tampering.

**Promotional Logic Security:**
Ensure promotional systems properly validate eligibility and prevent stacking of incompatible offers. Implement proper coupon validation and prevent reuse of single-use promotional codes. Use server-side calculation for all discounts and promotional benefits.

**Inventory and Resource Management:**
Implement proper inventory tracking and prevent overselling through race conditions or double-allocation. Use atomic operations for inventory updates and implement proper reservation systems for limited resources. Validate resource availability at transaction time rather than just during initial checks.

## G: Generative Path Checks

1. **Business Logic Mapping**: Are all business processes, workflows, and state machines properly documented and analyzed for bypass opportunities?
2. **Authorization Consistency**: Is object-level authorization consistently implemented across all API endpoints and data access points?
3. **State Management Security**: Are state transitions properly validated and controlled to prevent manipulation or bypass?
4. **Workflow Integrity**: Do multi-step processes properly validate prerequisites and prevent step skipping or reordering?
5. **Concurrency Controls**: Are race conditions and concurrent access properly handled for critical business operations?
6. **Integration Security**: Are external system integrations properly validated and secured against trust boundary violations?
7. **Financial Logic Validation**: Are all financial calculations, pricing logic, and economic transactions properly secured?
8. **Temporal Security**: Are time-based operations, token expiration, and temporal logic properly implemented?
9. **Cross-Request Security**: Are cross-request dependencies and multi-session operations properly secured?
10. **Trust Boundary Analysis**: Are all trust boundaries identified and properly secured with appropriate validation?

## U: Uncertainty Disclosure

**When uncertain about business logic security requirements**:
- Default to the most restrictive validation and authorization controls
- Implement comprehensive audit logging for all business logic operations
- Use established patterns for workflow security and state management
- Consult with business stakeholders to understand intended behavior and security requirements
- Apply defense-in-depth principles with multiple validation layers

**When business process complexity is unclear**:
- Map all possible execution paths and state transitions
- Implement comprehensive input validation alongside business logic validation
- Use formal verification techniques for critical business logic where possible
- Apply principle of least privilege and fail-secure defaults
- Implement comprehensive monitoring and anomaly detection for business logic violations

## A: Auditability

**Required Security Comments**:
- LOGIC_SECURITY: Mark all business logic validation and enforcement code
- STATE_VALIDATION: Document state management and transition control logic
- WORKFLOW_SECURITY: Document workflow step validation and prerequisite checking
- AUTHORIZATION_LOGIC: Document object-level authorization and access control implementation
- INTEGRATION_SECURITY: Document external system validation and trust boundary controls

**Logging Requirements**:
- Log all business logic violations and unauthorized access attempts with full context
- Monitor workflow bypass attempts and state manipulation activities
- Track privilege escalation attempts and authorization failures
- Include user context, business operation, and violation details in security logs
- Never log sensitive business data or financial information in security logs
- Implement real-time alerting for critical business logic violations

## R+D: Revision + Dialogue

**Security Review Questions**:
- "Are business rules consistently enforced across all application entry points and code paths?"
- "Can workflows be bypassed through step skipping, state manipulation, or race conditions?"
- "Are object ownership and tenant isolation properly validated for all data access operations?"
- "Do external integrations properly validate responses and implement trust boundary controls?"
- "Are financial calculations and economic logic properly secured against manipulation?"
- "Can privilege escalation occur through legitimate application features used in unintended ways?"
- "Are concurrent operations properly synchronized to prevent race conditions and double-spending?"
- "Do approval processes and administrative workflows prevent bypass through logic flaws?"

**Core Security Principle**:
Business logic security requires comprehensive validation of intended application behavior, proper enforcement of business rules across all execution paths, secure state management and workflow controls, and robust validation of trust boundaries and external integrations. Logic vulnerabilities cannot be prevented through input validation alone but require deep understanding of business processes and systematic security analysis of application workflows and state management.
