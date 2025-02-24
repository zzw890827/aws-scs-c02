# Amazon's AWS Certified Security - Specialty SCS-C02

1. A security engineer needs to develop a process to investigate and respond to potential security events on a company's Amazon EC2 instances. All the EC2 instances are backed by Amazon Elastic Block Store (Amazon EBS). The company uses AWS Systems Manager to manage all the EC2 instances and has installed Systems Manager Agent (SSM Agent) on all the EC2 instances. The process that the security engineer is developing must comply with AWS security best practices and must meet the following requirements: > A compromised EC2 instance's volatile memory and non-volatile memory must be preserved for forensic purposes. > A compromised EC2 instance's metadata must be updated with corresponding incident ticket information. - A compromised EC2 instance must remain online during the investigation but must be isolated to prevent the spread of malware. > Any investigative activity during the collection of volatile data must be captured as part of the process. Which combination of steps should the security engineer take to meet these requirements with the LEAST operational overhead? (Choose three.)
   - [ ] A. Gather any relevant metadata for the compromised EC2 instance. Enable termination protection. Isolate the instance by updating the instance's security groups to restrict access. Detach the instance from any Auto Scaling groups that the instance is a member of. Deregister the instance from any Elastic Load Balancing (ELB) resources.
   - [ ] B. Gather any relevant metadata for the compromised EC2 instance. Enable termination protection. Move the instance to an isolation subnet that denies all source and destination traffic. Associate the instance with the subnet to restrict access. Detach the instance from any Auto Scaling groups that the instance is a member of. Deregister the instance from any Elastic Load Balancing (ELB) resources.
   - [ ] C. Use Systems Manager Run Command to invoke scripts that collect volatile data.
   - [ ] D. Establish a Linux SSH or Windows Remote Desktop Protocol (RDP) session to the compromised EC2 instance to invoke scripts that collect volatile data.
   - [ ] E. Create a snapshot of the compromised EC2 instance's EBS volume for follow-up investigations. Tag the instance with any relevant metadata and incident ticket information.
   - [ ] F. Create a Systems Manager State Manager association to generate an EBS volume snapshot of the compromised EC2 instance. Tag the instance with any relevant metadata and incident ticket information.

   <details>
      <summary>Answer</summary>

      - A: In many AWS Incident Response (IR) guides, a common best practice is to create a dedicated “quarantine” or “isolation” security group that allows minimal (often SSM-only) ingress/egress. This approach typically involves less overhead (and fewer moving parts) than having to stop the instance and re-associate it to a new subnet—especially if you also need to preserve memory (because stopping the instance to move it would lose RAM).
      - C: Using Systems Manager Run Command (Option C) is preferred for No need for direct SSH/RDP, Better chain-of-custody and Automated central control
      - E: For a one-off IR process E is simpler and has less overhead. An ongoing State Manager association (Option F) is typically used for recurring tasks (e.g., regular backups). For forensic purposes, you only need to ensure you have at least one snapshot captured as soon as possible.

   </details>

2. A company needs a security engineer to implement a scalable solution for multi-account authentication and authorization. The solution should not introduce additional user-managed architectural components. Native AWS features should be used as much as possible. The security engineer has set up AWS Organizations with all features activated and AWS IAM Identity Center (AWS Single Sign-On) enabled. Which additional steps should the security engineer take to complete the task?
   - [ ] A. Use AD Connector to create users and groups for all employees that require access to AWS accounts. Assign AD Connector groups to AWS accounts and link to the IAM roles in accordance with the employees’ job functions and access requirements. Instruct employees to access AWS accounts by using the AWS Directory Service user portal.
   - [ ] B. Use an IAM Identity Center default directory to create users and groups for all employees that require access to AWS accounts. Assign groups to AWS accounts and link to permission sets in accordance with the employees’ job functions and access requirements. Instruct employees to access AWS accounts by using the IAM Identity Center user portal.
   - [ ] C. Use an IAM Identity Center default directory to create users and groups for all employees that require access to AWS accounts. Link IAM Identity Center groups to the IAM users present in all accounts to inherit existing permissions. Instruct employees to access AWS accounts by using the IAM Identity Center user portal.
   - [ ] D. Use AWS Directory Service for Microsoft Active Directory to create users and groups for all employees that require access to AWS accounts. Enable AWS Management Console access in the created directory and specify IAM Identity Center as a source of information for integrated accounts and permission sets. Instruct employees to access AWS accounts by using the AWS Directory Service user portal.

   <details>
      <summary>Answer</summary>

      - A: Wrong -> Using AD Connector typically involves an existing on-premises Microsoft Active Directory environment. This adds complexity and introduces external dependencies—not desired when you want an all-AWS-native approach without extra components.
      - B: Right.
      - C: Wrong -> This is not the recommended pattern. You should assign permission sets directly in IAM Identity Center rather than trying to inherit permissions from existing IAM users in each account. IAM Identity Center is meant to manage roles/permissions via permission sets, not by linking to legacy IAM users.
      - D: Wrong -> Although it is a fully managed AWS service, it is still a more complex setup than necessary if you just need a simple, cloud-native identity store for your AWS accounts. It also can introduce additional costs and maintenance overhead compared to using the default directory in IAM Identity Center.

   </details>

3. A company has an AWS account that hosts a production application. The company receives an email notification that Amazon GuardDuty has detected an Impact:IAMUser/AnomalousBehavior finding in the account. A security engineer needs to run the investigation playbook for this security incident and must collect and analyze the information without affecting the application. Which solution will meet these requirements MOST quickly?
   - [ ] A. Log in to the AWS account by using read-only credentials. Review the GuardDuty finding for details about the IAM credentials that were used. Use the IAM console to add a DenyAll policy to the IAM principal.
   - [ ] B. Log in to the AWS account by using read-only credentials. Review the GuardDuty finding to determine which API calls initiated the finding. Use Amazon Detective to review the API calls in context.
   - [ ] C. Log in to the AWS account by using administrator credentials. Review the GuardDuty finding for details about the IAM credentials that were used. Use the IAM console to add a DenyAll policy to the IAM principal.
   - [ ] D. Log in to the AWS account by using read-only credentials. Review the GuardDuty finding to determine which API calls initiated the finding. Use AWS CloudTrail Insights and AWS CloudTrail Lake to review the API calls in context.

   <details>
      <summary>Answer</summary>

      - A: Wrong -> This action may disrupt legitimate application functions if the IAM user is still needed.
      - B: Wrong -> While Amazon Detective provides great investigative tools, CloudTrail Insights and CloudTrail Lake are more suited for analyzing API anomalies at a detailed level. Amazon Detective is useful for broader security investigations but not necessarily the most quick way to analyze IAM anomalies.
      - C: Wrong -> Immediately applying a DenyAll policy without full investigation might cause unintended access issues.
      - D: Correct.
   </details>

4. A security engineer is designing an IAM policy to protect AWS API operations. The policy must enforce multi-factor authentication (MFA) for IAM users to access certain services in the AWS production account. Each session must remain valid for only 2 hours. Which combination of conditions must the security engineer add to the IAM policy to meet these requirements? (Choose two.) The current version of the IAM policy is as follows:

   ```json
   {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:StopInstances",
                "ec2:TerminateInstances"
            ],
            "Resource": ["*"]
        }]
   }
   ```

   - [ ] A. "Bool": {"aws:MultiFactorAuthPresent": "true"}
   - [ ] B. "Bool": {"aws:MultiFactorAuthPresent": "false"}
   - [ ] C. "NumericLessThan": {"aws:MultiFactorAuthAge": "7200"}
   - [ ] D. "NumericGreaterThan": {"aws:MultiFactorAuthAge": "7200"}
   - [ ] E. "NumericLessThan": {"MaxSessionDuration": "7200"}

   <details>
      <summary>Answer</summary>

      AC.

   </details>

5. A company uses AWS Organizations and has production workloads across multiple AWS accounts. A security engineer needs to design a solution that will proactively monitor for suspicious behavior across all the accounts that contain production workloads. The solution must automate remediation of incidents across the production accounts. The solution also must publish a notification to an Amazon Simple Notification Service (Amazon SNS) topic when a critical security finding is detected. In addition, the solution must send all security incident logs to a dedicated account. Which solution will meet these requirements?
   - [ ] A. Activate Amazon GuardDuty in each production account. In a dedicated logging account, aggregate all GuardDuty logs from each production account. Remediate incidents by configuring GuardDuty to directly invoke an AWS Lambda function. Configure the Lambda function to also publish notifications to the SNS topic.
   - [ ] B. Activate AWS Security Hub in each production account. In a dedicated logging account, aggregate all Security Hub findings from each production account. Remediate incidents by using AWS Config and AWS Systems Manager. Configure Systems Manager to also publish notifications to the SNS topic.
   - [ ] C. Activate Amazon GuardDuty in each production account. In a dedicated logging account, aggregate all GuardDuty logs from each production account. Remediate incidents by using Amazon EventBridge to invoke a custom AWS Lambda function from the GuardDuty findings. Configure the Lambda function to also publish notifications to the SNS topic.
   - [ ] D. Activate AWS Security Hub in each production account. In a dedicated logging account, aggregate all Security Hub findings from each production account. Remediate incidents by using Amazon EventBridge to invoke a custom AWS Lambda function from the Security Hub findings. Configure the Lambda function to also publish notifications to the SNS topic.

   <details>
      <summary>Answer</summary>

      - A: Wrong -> GuardDuty cannot directly invoke a Lambda. You would use EventBridge to capture GuardDuty findings and invoke a Lambda.
      - B: Wrong -> Security Hub alone is not the primary threat detection engine.
      - C: Right -> This is the classic and recommended pattern for automated threat detection and remediation in a multi-account environment.
      - D: Wrong -> Similar to B.

   </details>

6. A company is designing a multi-account structure for its development teams. The company is using AWS Organizations and AWS Single Sign-On (AWS SSO). The company must implement a solution so that the development teams can use only specific AWS Regions and so that each AWS account allows access to only specific AWS services. Which solution will meet these requirements with the LEAST operational overhead?
   - [ ] A. Use AWS SSO to set up service-linked roles with IAM policy statements that include the Condition, Resource, and NotAction elements to allow access to only the Regions and services that are needed.
   - [ ] B. Deactivate AWS Security Token Service (AWS STS) in Regions that the developers are not allowed to use.
   - [ ] C. Create SCPs that include the Condition, Resource, and NotAction elements to allow access to only the Regions and services that are needed.
   - [ ] D. For each AWS account, create tailored identity-based polic

   <details>
      <summary>Answer</summary>

      - A: While you can attach IAM policies to roles used by AWS SSO, you would have to manage these policies account-by-account or role-by-role. This increases operational overhead as your environment grows.
      - B: Deactivating STS in certain Regions partially addresses the Region restriction but does not help you control which services are accessible within the allowed Regions. It also can be cumbersome to manage STS activation/deactivation across many accounts.
      - C: Right.
      - D: Writing identity-based policies for each account is time-consuming and error-prone. You would need to maintain these policies across accounts as teams grow or requirements change.

   </details>

7. A company used a lift-and-shift approach to migrate from its on-premises data centers to the AWS Cloud. The company migrated on-premises VMs to Amazon EC2 instances. Now the company wants to replace some of components that are running on the EC2 instances with managed AWS services that provide similar functionality. Initially, the company will transition from load balancer software that runs on EC2 instances to AWS Elastic Load Balancers. A security engineer must ensure that after this transition, all the load balancer logs are centralized and searchable for auditing. The security engineer must also ensure that metrics are generated to show which ciphers are in use.
Which solution will meet these requirements?
   - [ ] A. Create an Amazon CloudWatch Logs log group. Configure the load balancers to send logs to the log group. Use the CloudWatch Logs console to search the logs. Create CloudWatch Logs filters on the logs for the required metrics.
   - [ ] B. Create an Amazon S3 bucket. Configure the load balancers to send logs to the S3 bucket. Use Amazon Athena to search the logs that are in the S3 bucket. Create Amazon CloudWatch filters on the S3 log files for the required metrics.
   - [ ] C. Create an Amazon S3 bucket. Configure the load balancers to send logs to the S3 bucket. Use Amazon Athena to search the logs that are in the S3 bucket. Create Athena queries for the required metrics. Publish the metrics to Amazon CloudWatch.
   - [ ] D. Create an Amazon CloudWatch Logs log group. Configure the load balancers to send logs to the log group. Use the AWS Management Console to search the logs. Create Amazon Athena queries for the required metrics. Publish the metrics to Amazon CloudWatch.

   <details>
      <summary>Answer</summary>

      - C is right. The best practice for ALB (or ELB) access logs is to write them to Amazon S3 rather than CloudWatch Logs. You can then use Amazon Athena to query and analyze those logs. If you need metrics (such as which ciphers are in use), you can create Athena queries that parse the logs and publish custom metrics to Amazon CloudWatch.

   </details>

8. A company has a legacy application that runs on a single Amazon EC2 instance. A security audit shows that the application has been using an IAM access key within its code to access an Amazon S3 bucket that is named DOC-EXAMPLE-BUCKET1 in the same AWS account. This access key pair has the s3:GetObject permission to all objects in only this S3 bucket. The company takes the application offline because the application is not compliant with the company’s security policies for accessing other AWS resources from Amazon EC2. A security engineer validates that AWS CloudTrail is turned on in all AWS Regions. CloudTrail is sending logs to an S3 bucket that is named DOC-EXAMPLE-BUCKET2. This S3 bucket is in the same AWS account as DOC-EXAMPLE-BUCKET1. However, CloudTrail has not been configured to send logs to Amazon CloudWatch Logs. The company wants to know if any objects in DOC-EXAMPLE-BUCKET1 were accessed with the IAM access key in the past 60 days. If any objects were accessed, the company wants to know if any of the objects that are text files (.txt extension) contained personally identifiable information (PII). Which combination of steps should the security engineer take to gather this information? (Choose two.)
   - [ ] A. Use Amazon CloudWatch Logs Insights to identify any objects in DOC-EXAMPLE-BUCKET1 that contain PII and that were available to the access key.
   - [ ] B. Use Amazon OpenSearch Service to query the CloudTrail logs in DOC-EXAMPLE-BUCKET2 for API calls that used the access key to access an object that contained PII.
   - [ ] C. Use Amazon Athena to query the CloudTrail logs in DOC-EXAMPLE-BUCKET2 for any API calls that used the access key to access an object that contained PII.
   - [ ] D. Use AWS Identity and Access Management Access Analyzer to identify any API calls that used the access key to access objects that contained PII in DOC-EXAMPLE-BUCKET1.
   - [ ] E. Configure Amazon Macie to identify any objects in DOC-EXAMPLE-BUCKET1 that contain PII and that were available to the access key.

   <details>
      <summary>Answer</summary>

      - C: Query the CloudTrail logs in Amazon S3 to find which objects were accessed by the IAM access key.This can be done by using Amazon Athena to query the CloudTrail logs in the S3 bucket (DOC-EXAMPLE-BUCKET2). Athena can parse CloudTrail’s JSON logs to show you all GetObject API calls made by that specific access key.
      - E: Determine if the accessed objects contain PII. You can configure Amazon Macie to scan the relevant objects in DOC-EXAMPLE-BUCKET1 to detect if any of those text files contain PII.

   </details>

9. A company hosts a web application on an Apache web server. The application runs on Amazon EC2 instances that are in an Auto Scaling group. The company configured the EC2 instances to send the Apache web server logs to an Amazon CloudWatch Logs group that the company has configured to expire after 1 year. Recently, the company discovered in the Apache web server logs that a specific IP address is sending suspicious requests to the web application. A security engineer wants to analyze the past week of Apache web server logs to determine how many requests that the IP address sent and the corresponding URLs that the IP address requested. What should the security engineer do to meet these requirements with the LEAST effort?
   - [ ] A. Export the CloudWatch Logs group data to Amazon S3. Use Amazon Macie to query the logs for the specific IP address and the requested URL.
   - [ ] B. Configure a CloudWatch Logs subscription to stream the log group to an Amazon OpenSearch Service cluster. Use OpenSearch Service to analyze the logs for the specific IP address and the requested URLs.
   - [ ] C. Use CloudWatch Logs Insights and a custom query syntax to analyze the CloudWatch logs for the specific IP address and the requested URLs.
   - [ ] D. Export the CloudWatch Logs group data to Amazon S3. Use AWS Glue to crawl the S3 bucket for only the log entries that contain the specific IP address. Use AWS Glue to view the results.

   <details>
      <summary>Answer</summary>

      - C: The easiest and most efficient solution is to analyze the logs directly in Amazon CloudWatch Logs using CloudWatch Logs Insights. This option eliminates the need to set up additional infrastructure or export data to other services.

   </details>

10. While securing the connection between a company's VPC and its on-premises data center, a Security Engineer sent a ping command from an on-premises host (IP address 203.0.113.12) to an Amazon EC2 instance (IP address 172.31.16.139). The ping command did not return a response. hat action should be performed to allow the ping to work? The flow log in the VPC showed the following:

    ```bash
    2 123456789010 eni-1235b8ca 203.0.113.12 172.31.16.139 0 0 1 4 336 1432917027 1432917142 ACCEPT OK
    2 123456789010 eni-1235b8ca 172.31.16.139 203.0.113.12 0 0 1 4 336 1432917094 1432917142 REJECT OK
    ```

    - [ ] A. In the security group of the EC2 instance, allow inbound ICMP traffic.
    - [ ] B. In the security group of the EC2 instance, allow outbound ICMP traffic.
    - [ ] C. In the VPC's NACL, allow inbound ICMP traffic.
    - [ ] D. In the VPC's NACL, allow outbound ICMP traffic.

    <details>
       <summary>Answer</summary>

       - D: From the flow log entries, you can see that inbound traffic (203.0.113.12 → 172.31.16.139) is ACCEPT but the outbound traffic (172.31.16.139 → 203.0.113.12) is REJECT. Security groups in AWS are stateful, meaning that if inbound traffic is allowed, then the corresponding response traffic is automatically allowed outbound. Network ACLs, however, are stateless, so you must explicitly allow both inbound and outbound traffic. Since the outbound ICMP response is being rejected, the missing rule is in the Network ACL egress rules. You need to allow outbound ICMP in the VPC’s NACL so that the Echo Reply can reach the on-premises host.

    </details>

11. A company is expanding its group of stores. On the day that each new store opens, the company wants to launch a customized web application for that store. Each store's application will have a non-production environment and a production environment. Each environment will be deployed in a separate AWS account. The company uses AWS Organizations and has an OU that is used only for these accounts. The company distributes most of the development work to third-party development teams. A security engineer needs to ensure that each team follows the company's deployment plan for AWS resources. The security engineer also must limit access to the deployment plan to only the developers who need access. The security engineer already has created an AWS CloudFormation template that implements the deployment plan. What should the security engineer do next to meet the requirements in the MOST secure way?
    - [ ] A. Create an AWS Service Catalog portfolio in the organization's management account. Upload the CloudFormation template. Add the template to the portfolio's product list. Share the portfolio with the OU.
    - [ ] B. Use the CloudFormation CLI to create a module from the CloudFormation template. Register the module as a private extension in the CloudFormation registry. Publish the extension. In the OU, create an SCP that allows access to the extension.
    - [ ] C. Create an AWS Service Catalog portfolio in the organization's management account. Upload the CloudFormation template. Add the template to the portfolio's product list. Create an IAM role that has a trust policy that allows cross-account access to the portfolio for users in the OU accounts. Attach the AWSServiceCatalogEndUserFullAccess managed policy to the role.
    - [ ] D. Use the CloudFormation CLI to create a module from the CloudFormation template. Register the module as a private extension in the CloudFormation registry. Publish the extension. Share the extension with the OU.

    <details>
       <summary>Answer</summary>

       - C: The best practice in this scenario is to distribute the standardized CloudFormation template via AWS Service Catalog, because Service Catalog allows you to:
         - Centrally manage and version your CloudFormation templates (as “products”).
         - Share those products across multiple AWS accounts in an Organization.
         - Apply fine-grained access control so that only authorized users (e.g., specific developer groups) can launch the products.

    </details>

12. An ecommerce company has a web application architecture that runs primarily on containers. The application containers are deployed on Amazon Elastic Container Service (Amazon ECS). The container images for the application are stored in Amazon Elastic Container Registry (Amazon ECR). The company's security team is performing an audit of components of the application architecture. The security team identifies issues with some container images that are stored in the container repositories. The security team wants to address these issues by implementing continual scanning and on-push scanning of the container images. The security team needs to implement a solution that makes any findings from these scans visible in a centralized dashboard. The security team plans to use the dashboard to view these findings along with other security-related findings that they intend to generate in the future. There are specific repositories that the security team needs to exclude from the scanning process. Which solution will meet these requirements?
    - [ ] A. Use Amazon Inspector. Create inclusion rules in Amazon ECR to match repositories that need to be scanned. Push Amazon Inspector findings to AWS Security Hub.
    - [ ] B. Use ECR basic scanning of container images. Create inclusion rules in Amazon ECR to match repositories that need to be scanned. Push findings to AWS Security Hub.
    - [ ] C. Use ECR basic scanning of container images. Create inclusion rules in Amazon ECR to match repositories that need to be scanned. Push findings to Amazon Inspector.
    - [ ] D. Use Amazon Inspector. Create inclusion rules in Amazon Inspector to match repositories that need to be scanned. Push Amazon Inspector findings to AWS Config.

    <details>
       <summary>Answer</summary>

       - A: Correct -> By enabling ECR Enhanced scanning (powered by Amazon Inspector), you get the required continual and on-push scanning. You can specify which repositories should be included for scanning, and the findings can be sent to AWS Security Hub.
       - B: Incorrect -> Basic scanning does not support continual (ongoing) scanning. It only scans at image push or on-demand.
       - C: Incorrect -> ECR basic scanning does not push findings to Inspector. There is no mechanism for `pushing` basic-scan results into Amazon Inspector.
       - D: Incorrect -> It specifies sending findings to AWS Config, which is not the correct central security dashboard. The requirement is to view findings alongside other security findings, which is exactly what AWS Security Hub is for.

    </details>

13. A company is running internal microservices on Amazon Elastic Container Service (Amazon ECS) with the Amazon EC2 launch type. The company is using Amazon Elastic Container Registry (Amazon ECR) private repositories. A security engineer needs to encrypt the private repositories by using AWS Key Management Service (AWS KMS). The security engineer also needs to analyze the container images for any common vulnerabilities and exposures (CVEs). Which solution will meet these requirements?
    - [ ] A. Enable KMS encryption on the existing ECR repositories. Install Amazon Inspector Agent from the ECS container instances’ user data. Run an assessment with the CVE rules.
    - [ ] B. Recreate the ECR repositories with KMS encryption and ECR scanning enabled. Analyze the scan report after the next push of images.
    - [ ] C. Recreate the ECR repositories with KMS encryption and ECR scanning enabled. Install AWS Systems Manager Agent on the ECS container instances. Run an inventory report.
    - [ ] D. Enable KMS encryption on the existing ECR repositories. Use AWS Trusted Advisor to check the ECS container instances and to verily the findings against a list of current CVEs.

    <details>
       <summary>Answer</summary>

       - A: Incorrect ->  `Enable KMS encryption on existing repositories` is not feasible for a customer managed key. You also do not necessarily need to install Amazon Inspector agents just to scan images—ECR can do that natively.
       - B: Correct -> Recreate the ECR repository with the KMS CMK specified (so the images at rest are encrypted using your customer managed key). Enable ECR scanning (scanOnPush) to scan images for CVEs. Analyze the ECR scan report after the images are pushed.
       - C: Incorrect -> Installing the AWS Systems Manager Agent and running an inventory report will not provide a vulnerability (CVE) analysis of container images.
       - D: Incorrect -> Trusted Advisor does not check container images for CVEs. It provides best-practice checks but not detailed vulnerability scans of container images.

    </details>

14. A company manages multiple AWS accounts using AWS Organizations. The company's security team notices that some member accounts are not sending AWS CloudTrail logs to a centralized Amazon S3 logging bucket. The security team wants to ensure there is at least one trail configured for all existing accounts and for any account that is created in the future. Which set of actions should the security team implement to accomplish this?
    - [ ] A. Create a new trail and configure it to send CloudTrail logs to Amazon S3. Use Amazon EventBridge to send notification if a trail is deleted or stopped.
    - [ ] B. Deploy an AWS Lambda function in every account to check if there is an existing trail and create a new trail, if needed.
    - [ ] C. Edit the existing trail in the Organizations management account and apply it to the organization.
    - [ ] D. Create an SCP to deny the `cloudtrail:Delete* and cloudtrail:Stop*` actions. Apply the SCP to all accounts.

    <details>
       <summary>Answer</summary>

       - A: Incorrect -> While EventBridge rules can help you detect changes (like a trail being deleted or stopped), this option doesn't ensure that every existing member account or new account automatically has a CloudTrail configured unless you specifically set it as an organization trail. Notifications alone do not enforce consistent coverage.
       - B: InCorrect -> This option is unnecessarily complex. Managing Lambda functions in every account (especially as the number of accounts grows) becomes burdensome. It also doesn't guarantee future accounts will have CloudTrail unless you have an automated deployment mechanism. An organization trail is a simpler, more scalable solution.
       - C: Correct.
       - D: Incorrect -> An SCP (Service Control Policy) can prevent users and roles in member accounts from deleting or stopping CloudTrail, but by itself does not ensure that CloudTrail is enabled in the first place. You still need an organization trail to guarantee that logs are being collected and sent to S3.

    </details>

15. A company that uses AWS Organizations is using AWS IAM Identity Center (AWS Single Sign-On) to administer access to AWS accounts. A security engineer is creating a custom permission set in IAM Identity Center. The company will use the permission set across multiple accounts. An AWS managed policy and a customer managed policy are attached to the permission set. The security engineer has full administrative permissions and is operating in the management account. When the security engineer attempts to assign the permission set to an IAM Identity Center user who has access to multiple accounts, the assignment fails. What should the security engineer do to resolve this failure?
    - [ ] A. Create the customer managed policy in every account where the permission set is assigned. Give the customer managed policy the same name and same permissions in each account.
    - [ ] B. Remove either the AWS managed policy or the customer managed policy from the permission set. Create a second permission set that includes the removed policy. Apply the permission sets separately to the user.
    - [ ] C. Evaluate the logic of the AWS managed policy and the customer managed policy. Resolve any policy conflicts in the permission set before deployment.
    - [ ] D. Do not add the new permission set to the user. Instead, edit the user's existing permission set to include the AWS managed policy and the customer managed policy.

    <details>
       <summary>Answer</summary>

       - A -> The issue arises because a customer managed policy must exist in each account where the permission set (which references that policy) is assigned. If it is missing in any target account, the assignment will fail. Therefore, the correct solution is to ensure that the policy is present in every target account.

    </details>

16. A security engineer is using AWS Organizations and wants to optimize SCPs. The security engineer needs to ensure that the SCPs conform to best practices. Which approach should the security engineer take to meet this requirement?
    - [ ] A. Use AWS IAM Access Analyzer to analyze the polices. View the findings from policy validation checks.
    - [ ] B. Review AWS Trusted Advisor checks for all accounts in the organization.
    - [ ] C. Set up AWS Audit Manager. Run an assessment for all AWS Regions for all accounts.
    - [ ] D. Ensure that Amazon Inspector agents are installed on all Amazon EC2 instances in all accounts.

    <details>
       <summary>Answer</summary>

       - A: Correct -> The best way to ensure that Service Control Policies (SCPs) conform to AWS best practices is to use AWS IAM Access Analyzer. Specifically, you can use policy validation in IAM Access Analyzer to analyze and validate your SCPs.
       - B: Inccorect -> AWS Trusted Advisor provides checks across cost optimization, security, and other categories, but it does not give detailed policy-level validation or recommendations for SCPs.
       - C: Incorrect -> AWS Audit Manager is designed for automating compliance audits, not specifically for validating the structure and correctness of SCPs.
       - D: Incorrect -> Amazon Inspector focuses on finding security vulnerabilities and deviations on Amazon EC2 instances, not on validating IAM or Organizations policies.

    </details>

17. A company uses Amazon RDS for MySQL as a database engine for its applications. A recent security audit revealed an RDS instance that is not compliant with company policy for encrypting data at rest. A security engineer at the company needs to ensure that all existing RDS databases are encrypted using server-side encryption and that any future deviations from the policy are detected. Which combination of steps should the security engineer take to accomplish this? (Choose two.)
    - [ ] A. Create an AWS Config rule to detect the creation of encrypted RDS databases. Create an Amazon EventBridge (Amazon CloudWatch Events) rule to trigger on the AWS Config rules compliance state change and use Amazon Simple Notification Service (Amazon SNS) to notify the security operations team.
    - [ ] B. Use AWS System Manager State Manager to detect RDS database encryption configuration drift. Create an Amazon EventBridge (Amazon CloudWatch Events) rule to track state changes and use Amazon Simple Notification Service (Amazon SNS) to notify the security operations team.
    - [ ] C. Create a read replica for the existing unencrypted RDS database and enable replica encryption in the process. Once the replica becomes active, promote it into a standalone database instance and terminate the unencrypted database instance.
    - [ ] D. Take a snapshot of the unencrypted RDS database. Copy the snapshot and enable snapshot encryption in the process. Restore the database instance from the newly created encrypted snapshot. Terminate the unencrypted database instance.
    - [ ] E. Enable encryption for the identified unencrypted RDS instance by changing the configurations of the existing database.

    <details>
       <summary>Answer</summary>

       - A: Correct -> This ensures that any future RDS instances created without encryption are quickly detected, and the appropriate team is notified.
       - D: Correct -> Since you cannot directly enable encryption on an existing RDS database that is already running, this approach is the standard way to convert an unencrypted RDS database to an encrypted one.

    </details>

18. A company has recently recovered from a security incident that required the restoration of Amazon EC2 instances from snapshots. After performing a gap analysis of its disaster recovery procedures and backup strategies, the company is concerned that, next time, it will not be able to recover the EC2 instances if the AWS account was compromised and Amazon EBS snapshots were deleted. All EBS snapshots are encrypted using an AWS KMS CMK. Which solution would solve this problem?
    - [ ] A. Create a new Amazon S3 bucket. Use EBS lifecycle policies to move EBS snapshots to the new S3 bucket. Move snapshots to Amazon S3 Glacier using lifecycle policies, and apply Glacier Vault Lock policies to prevent deletion.
    - [ ] B. Use AWS Systems Manager to distribute a configuration that performs local backups of all attached disks to Amazon S3.
    - [ ] C. Create a new AWS account with limited privileges. Allow the new account to access the AWS KMS key used to encrypt the EBS snapshots, and copy the encrypted snapshots to the new account on a recurring basis.
    - [ ] D. Use AWS Backup to copy EBS snapshots to Amazon S3.

    <details>
       <summary>Answer</summary>

       - A: Incorrect -> While this approach can prevent deletion with Glacier Vault Lock, it does not protect against account compromise because an attacker with full account access could disable lifecycle policies and delete the data.
       - D: Incorrect -> Local backups do not address the issue of protecting EBS snapshots in case of account compromise. If the account is compromised, S3 backups could also be at risk.
       - C: Correct -> If the primary AWS account is compromised, there is a risk that the EBS snapshots could be deleted. To address this risk, a robust solution would involve:
         - Isolating backups in a separate AWS account: By creating a new AWS account with minimal privileges and regularly copying snapshots to that account, you can ensure that the snapshots are secure even if the primary account is compromised.
         - KMS key access for encryption: The new account must have access to the AWS KMS Customer Master Key (CMK) used to encrypt the snapshots, ensuring it can decrypt and use the snapshots.
         - Recurrence for reliability: Automating the process of copying snapshots ensures that backups are consistently available in the secondary account.
       - D: Incorrect: WS Backup alone does not provide cross-account protection. If the account is compromised, both the original and backup snapshots may be deleted.

    </details>

19. A company discovers a billing anomaly in its AWS account. A security consultant investigates the anomaly and discovers that an employee who left the company 30 days ago still has access to the account. The company has not monitored account activity in the past. The security consultant needs to determine which resources have been deployed or reconfigured by the employee as quickly as possible. Which solution will meet these requirements?
    - [ ] A. In AWS Cost Explorer, filter chart data to display results from the past 30 days. Export the results to a data table. Group the data table by resource.
    - [ ] B. Use AWS Cost Anomaly Detection to create a cost monitor. Access the detection history. Set the time frame to Last 30 days. In the search area, choose the service category.
    - [ ] C. In AWS CloudTrail, filter the event history to display results from the past 30 days. Create an Amazon Athena table that contains the data. Partition the table by event source.
    - [ ] D. Use AWS Audit Manager to create an assessment for the past 30 days. Apply a usage-based framework to the assessment. Configure the assessment to assess by resource.

    <details>
       <summary>Answer</summary>

       - A: Incorrect -> Cost Explorer provides cost-related insights but does not offer detailed records of resource deployment or reconfiguration actions. It only shows cost trends, not specific activities.
       - B: Incorrect -> Cost Anomaly Detection identifies unusual spending patterns but does not provide details about who performed specific actions or what resources were affected.
       - C: Correct
         - CloudTrail logs API activity in an AWS account, providing detailed records of all actions taken by users, roles, or AWS services. This makes it the most reliable service for identifying specific resource-related actions performed by the employee.
         - You can filter CloudTrail event history to show activities within a specific time frame, such as the past 30 days, and identify actions tied to the former employee's credentials.
         - Exporting the logs to Amazon Athena allows you to query the data efficiently. Partitioning the table by event source makes queries faster and more targeted.
       - D: Audit Manager helps automate audit processes and compliance checks. It is not designed to identify specific activities performed by an individual within a given timeframe.

    </details>

20. A company has an AWS Lambda function that creates image thumbnails from larger images. The Lambda function needs read and write access to an Amazon S3 bucket in the same AWS account. Which solutions will provide the Lambda function this access? (Choose two.)
    - [ ] A. Create an IAM user that has only programmatic access. Create a new access key pair. Add environmental variables to the Lambda function with the access key ID and secret access key. Modify the Lambda function to use the environmental variables at run time during communication with Amazon S3.
    - [ ] B. Generate an Amazon EC2 key pair. Store the private key in AWS Secrets Manager. Modify the Lambda function to retrieve the private key from Secrets Manager and to use the private key during communication with Amazon S3.
    - [ ] C. Create an IAM role for the Lambda function. Attach an IAM policy that allows access to the S3 bucket.
    - [ ] D. Create an IAM role for the Lambda function. Attach a bucket policy to the S3 bucket to allow access. Specify the function's IAM role as the principal.
    - [ ] E. Create a security group. Attach the security group to the Lambda function. Attach a bucket policy that allows access to the S3 bucket through the security group ID.

    <details>
       <summary>Answer</summary>

       C, D. These two approaches are the recommended best practices for granting a Lambda function access to an S3 bucket. You either attach a policy to the Lambda execution role (option C) or use a resource-based bucket policy that allows the Lambda's execution role as a principal (option D).

    </details>

21. A company's AWS CloudTrail logs are all centrally stored in an Amazon S3 bucket. The security team controls the company's AWS account. The security team must prevent unauthorized access and tampering of the CloudTrail logs. Which combination of steps should the security team take? (Choose three.)
    - [ ] A. Configure server-side encryption with AWS KMS managed encryption keys (SSE-KMS).
    - [ ] B. Compress log files with secure gzip.
    - [ ] C. Create an Amazon EventBridge rule to notify the security team of any modifications on CloudTrail log files.
    - [ ] D. Implement least privilege access to the S3 bucket by configuring a bucket policy.
    - [ ] E. Configure CloudTrail log file integrity validation.
    - [ ] F. Configure Access Analyzer for S3.

    <details>
       <summary>Answer</summary>

       - A -> Ensures that all CloudTrail log files at rest are encrypted using a customer-managed KMS key. This helps maintain confidentiality and integrity by requiring the appropriate KMS permissions to decrypt and read the logs.
       - D -> Restricts who can put objects into and read objects from the S3 bucket. Typically, you allow AWS CloudTrail to write logs and grant only the security team read access. This prevents unauthorized users or services from accessing or manipulating the logs.
       - E -> Enables you to verify that the log files were not altered or tampered with after AWS CloudTrail delivered them. When integrity validation is enabled, CloudTrail creates a digest file with a checksum for each log file, which you can use to confirm the log file's integrity.

    </details>

22. A-company uses a third-party identity provider and SAML-based SSO for its AWS accounts. After the third-party identity provider renewed an expired signing certificate, users saw the following message when trying to log in: Error: Response Signature Invalid (Service: AWSSecurityTokenService; Status Code: 400; Error Code: InvalidIdentityToken) A security engineer needs to provide a solution that corrects the error and minimizes operational overhead. Which solution meets these requirements?
    - [ ] A. Upload the third-party signing certificate’s new private key to the AWS identity provider entity defined in AWS Identity and Access Management (IAM) by using the AWS Management Console.
    - [ ] B. Sign the identity provider's metadata file with the new public key. Upload the signature to the AWS identity provider entity defined in AWS Identity and Access Management (IAM) by using the AWS CLI.
    - [ ] C. Download the updated SAML metadata file from the identity service provider. Update the file in the AWS identity provider entity defined in AWS Identity and Access Management (IAM) by using the AWS CLI.
    - [ ] D. Configure the AWS identity provider entity defined in AWS Identity and Access Management (IAM) to synchronously fetch the new public key by using the AWS Management Console.

    <details>
       <summary>Answer</summary>

       C is correct. When an IdP’s certificate is rotated, the standard procedure is to update the SAML metadata in AWS so that AWS has the new public key and can validate the signed SAML assertions. Specifically:
       - Download the updated SAML metadata (which includes the new certificate) from your IdP.
       - Update the metadata in the AWS identity provider resource in IAM (either via the console or CLI).

    </details>

23. A company has several workloads running on AWS. Employees are required to authenticate using on-premises ADFS and SSO to access the AWS Management Console. Developers migrated an existing legacy web application to an Amazon EC2 instance. Employees need to access this application from anywhere on the internet, but currently, there is no authentication system built into the application. How should the Security Engineer implement employee-only access to this system without changing the application?
    - [ ] A. Place the application behind an Application Load Balancer (ALB). Use Amazon Cognito as authentication for the ALB. Define a SAML-based Amazon Cognito user pool and connect it to ADFS.
    - [ ] B. Implement AWS SSO in the master account and link it to ADFS as an identity provider. Define the EC2 instance as a managed resource, then apply an IAM policy on the resource.
    - [ ] C. Define an Amazon Cognito identity pool, then install the connector on the Active Directory server. Use the Amazon Cognito SDK on the application instance to authenticate the employees using their Active Directory user names and passwords.
    - [ ] D. Create an AWS Lambda custom authorizer as the authenticator for a reverse proxy on Amazon EC2. Ensure the security group on Amazon EC2 only allows access from the Lambda function.

    <details>
       <summary>Answer</summary>

       - A: Correct ->
         - ALB supports integrating authentication mechanisms without modifying the underlying application. You can use ALB listener rules to enforce authentication for accessing the application.
         - Amazon Cognito provides built-in integration with federated identity providers like ADFS. You can set up a SAML-based Cognito user pool and configure it to authenticate users via ADFS. Once authenticated, employees can access the legacy application.
       - B: Incorrect -> AWS SSO does not directly control access to EC2-hosted web applications. It is primarily designed for managing access to AWS Management Console, CLI, and SDKs, not web applications hosted on EC2.
       - C: Incorrect -> This approach requires modifying the application to integrate the Cognito SDK for authentication, which contradicts the requirement to avoid changing the application.
       - D: Incorrect -> This is a highly custom solution that requires significant effort to build and manage, making it unnecessarily complex. It also does not leverage ADFS and SAML for seamless employee authentication.

    </details>

24. A company is using AWS to run a long-running analysis process on data that is stored in Amazon S3 buckets. The process runs on a fleet of Amazon EC2 instances that are in an Auto Scaling group. The EC2 instances are deployed in a private subnet of a VPC that does not have internet access. The EC2 instances and the S3 buckets are in the same AWS account. The EC2 instances access the S3 buckets through an S3 gateway endpoint that has the default access policy. Each EC2 instance is associated with an instance profile role that has a policy that explicitly allows the s3:GetObject action and the s3:PutObject action for only the required S3 buckets. The company learns that one or more of the EC2 instances are compromised and are exfiltrating data to an S3 bucket that is outside the company's organization in AWS Organizations. A security engineer must implement a solution to stop this exfiltration of data and to keep the EC2 processing job functional. Which solution will meet these requirements?
    - [ ] A. Update the policy on the S3 gateway endpoint to allow the S3 actions only if the values of the aws:ResourceOrgID and aws:PrincipalOrgID condition keys match the company's values.
    - [ ] B. Update the policy on the instance profile role to allow the S3 actions only if the value of the aws:ResourceOrgID condition key matches the company's value.
    - [ ] C. Add a network ACL rule to the subnet of the EC2 instances to block outgoing connections on port 443.
    - [ ] D. Apply an SCP on the AWS account to allow the S3 actions only if the values of the aws:ResourceOrgID and aws:PrincipalOrgID condition keys match the company's values.

    <details>
       <summary>Answer</summary>

       A is correct. The EC2 instances are compromised, and data is being exfiltrated to an external S3 bucket. The goal is to restrict access so that the EC2 instances can only interact with S3 buckets within the company's AWS Organization while maintaining the functionality of the analysis process. The S3 gateway endpoint policy acts as a gatekeeper for traffic between the EC2 instances and S3. By updating the gateway endpoint policy to include conditions using aws:ResourceOrgID and aws:PrincipalOrgID, you can enforce that only requests involving S3 buckets within the company’s AWS Organization are allowed.

       - aws:ResourceOrgID: Ensures the destination S3 bucket belongs to the company’s AWS Organization.
       - aws:PrincipalOrgID: Ensures the entity (in this case, the EC2 instance role) belongs to the company’s AWS Organization.

    </details>

25. A company that operates in a hybrid cloud environment must meet strict compliance requirements. The company wants to create a report that includes evidence from on-premises workloads alongside evidence from AWS resources. A security engineer must implement a solution to collect, review, and manage the evidence to demonstrate compliance with company policy. Which solution will meet these requirements?
    - [ ] A. Create an assessment in AWS Audit Manager from a prebuilt framework or a custom framework. Upload manual evidence from the on-premises workloads. Add the evidence to the assessment. Generate an assessment report after Audit Manager collects the necessary evidence from the AWS resources.
    - [ ] B. Install the Amazon CloudWatch agent on the on-premises workloads. Use AWS Config to deploy a conformance pack from a sample conformance pack template or a custom YAML template. Generate an assessment report after AWS Config identifies noncompliant workloads and resources.
    - [ ] C. Set up the appropriate security standard in AWS Security Hub. Upload manual evidence from the on-premises workloads. Wait for Security Hub to collect the evidence from the AWS resources. Download the list of controls as a .csv file.
    - [ ] D. Install the Amazon CloudWatch agent on the on-premises workloads. Create a CloudWatch dashboard to monitor the on-premises workloads and the AWS resources. Run a query on the workloads and resources. Download the results.

    <details>
       <summary>Answer</summary>

       - A: Correct -> AWS Audit Manager is specifically designed for compliance reporting and auditing. It allows you to create an assessment using prebuilt frameworks (like PCI DSS or GDPR) or custom frameworks tailored to the company's compliance requirements. You can upload manual evidence for on-premises workloads and add it to the assessment, alongside evidence automatically collected from AWS resources. Audit Manager provides a consolidated assessment report that combines evidence from both sources, making it ideal for hybrid cloud environments and compliance demonstration.
       - B: Incorrect -> AWS Config and conformance packs are useful for monitoring compliance with specific configuration rules and standards. However, AWS Config cannot collect or integrate evidence from on-premises workloads, and it is not designed for generating comprehensive compliance reports that combine on-premises and AWS evidence.
       - C: Incorrect -> AWS Security Hub helps monitor and aggregate security findings across AWS accounts and regions. However, Security Hub does not support manual evidence uploads from on-premises workloads, and its reports (e.g., .csv files of controls) do not align with compliance reporting requirements.
       - D: Incorrect -> Amazon CloudWatch is primarily a monitoring and logging service, not a compliance tool.

    </details>

26. A security engineer logs in to the AWS Lambda console with administrator permissions. The security engineer is trying to view logs in Amazon CloudWatch for a Lambda function that is named myFunction. When the security engineer chooses the option in the Lambda console to view logs in CloudWatch, an "error loading Log Streams" message appears. How should the security engineer correct the error? The IAM policy for the Lambda function's execution role contains the following:

    ```json
    {
       "Version": "2012-10-17",
       "Statement": [
          {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:us-east-1:1111111111:*"
          },
          {
            "Effect": "Allow",
            "Action": ["logs:PutLogEvents"]
            "Resource": "arn:aws:logs:us-east-1:1111111111:log-group:/aws/lambda/myFunction:*"
          }
      ]
    }
    ```

    - [ ] A. Move the logs:CreateLogGroup action to the second Allow statement.
    - [ ] B. Add the logs:PutDestination action to the second Allow statement.
    - [ ] C. Add the logs:GetLogEvents action to the second Allow statement.
    - [ ] D. Add the logs:CreateLogStream action to the second Allow statement.

    <details>
       <summary>Answer</summary>

       A is correct. The error occurs when the Lambda function cannot log events to Amazon CloudWatch Logs. This typically happens if the execution role lacks sufficient permissions to create a log stream or put log events into it.

    </details>

27. A company purchased a subscription to a third-party cloud security scanning solution that integrates with AWS Security Hub. A security engineer needs to implement a solution that will remediate the findings from the third-party scanning solution automatically. Which solution will meet this requirement?
    - [ ] A. Set up an Amazon EventBridge rule that reacts to new Security Hub findings. Configure an AWS Lambda function as the target for the rule to remediate the findings.
    - [ ] B. Set up a custom action in Security Hub. Configure the custom action to call AWS Systems Manager Automation runbooks to remediate the findings.
    - [ ] C. Set up a custom action in Security Hub. Configure an AWS Lambda function as the target for the custom action to remediate the findings.
    - [ ] D. Set up AWS Config rules to use AWS Systems Manager Automation runbooks to remediate the findings.

    <details>
       <summary>Answer</summary>

       - A: Correct -> Amazon EventBridge can monitor Security Hub findings in near real-time by reacting to events that represent new findings. The Lambda function acts as the remediation logic. It is highly customizable and can perform actions such as updating security configurations, notifying teams, or initiating remediation workflows specific to the findings.
       - B: Incorrect -> Custom actions in Security Hub are user-triggered and do not execute automatically. Since the requirement specifies automatic remediation, this option is not suitable.
       - C: Incorrect -> Similar to B.
       - D: Incorrect -> AWS Config rules work well for compliance checks and remediation based on resource configuration changes, but they are not directly designed to handle findings from Security Hub or a third-party scanning solution in real-time.

    </details>

28. An application is running on an Amazon EC2 instance that has an IAM role attached. The IAM role provides access to an AWS Key Management Service (AWS KMS) customer managed key and an Amazon S3 bucket. The key is used to access 2 TB of sensitive data that is stored in the S3 bucket. A security engineer discovers a potential vulnerability on the EC2 instance that could result in the compromise of the sensitive data. Due to other critical operations, the security engineer cannot immediately shut down the EC2 instance for vulnerability patching. What is the FASTEST way to prevent the sensitive data from being exposed?
    - [ ] A. Download the data from the existing S3 bucket to a new EC2 instance. Then delete the data from the S3 bucket. Re-encrypt the data with a client-based key. Upload the data to a new S3 bucket.
    - [ ] B. Block access to the public range of S3 endpoint IP addresses by using a host-based firewall. Ensure that internet-bound traffic from the affected EC2 instance is routed through the host-based firewall.
    - [ ] C. Revoke the IAM role's active session permissions. Update the S3 bucket policy to deny access to the IAM role. Remove the IAM role from the EC2 instance profile.
    - [ ] D. Disable the current key. Create a new KMS key that the IAM role does not have access to, and re-encrypt all the data with the new key. Schedule the compromised key for deletion.

    <details>
       <summary>Answer</summary>

       - A: Incorrect -> This is not feasible for 2 TB of data because downloading, re-encrypting, and re-uploading the data to a new S3 bucket is time-consuming and does not immediately prevent exposure.
       - B: Incorrect -> Blocking access to the public S3 endpoint IPs using a host-based firewall is complex to configure and not a guaranteed way to block access to the S3 bucket since IAM permissions still allow access from the instance.
       - C: Correct ->
         - Revoking the IAM role's active session permissions: This action immediately invalidates any temporary security credentials that the EC2 instance may already be using to access AWS resources.
         - Updating the S3 bucket policy to deny access to the IAM role: This ensures that even if there are remaining valid credentials, access to the sensitive data in the S3 bucket is explicitly blocked.
         - Removing the IAM role from the EC2 instance profile: Prevents any further access attempts from the EC2 instance to AWS resources.
       - D: isabling the KMS key and re-encrypting the data with a new key involves significant time, especially for 2 TB of data. It is not a quick solution to prevent exposure.

    </details>

29. A security engineer is configuring account-based access control (ABAC) to allow only specific principals to put objects into an Amazon S3 bucket. The principals already have access to Amazon S3. The security engineer needs to configure a bucket policy that allows principals to put objects into the S3 bucket only if the value of the Team tag on the object matches the value of the Team tag that is associated with the principal. During testing, the security engineer notices that a principal can still put objects into the S3 bucket when the tag values do not match. Which combination of factors are causing the PutObject operation to succeed when the tag values are different? (Choose two.)
    - [ ] A. The principal's identity-based policy grants access to put objects into the S3 bucket with no conditions.
    - [ ] B. The principal's identity-based policy overrides the condition because the identity-based policy contains an explicit allow.
    - [ ] C. The S3 bucket's resource policy does not deny access to put objects.
    - [ ] D. The S3 bucket's resource policy cannot allow actions to the principal.
    - [ ] E. The bucket policy does not apply to principals in the same zone of trust.

    <details>
       <summary>Answer</summary>

       Answer is AC.
       AWS policy evaluation logic boils down to:

       - If there is at least one explicit “Allow” from any policy (identity-based or resource-based),
       - AND there is no explicit “Deny” from any policy,
       - …then the request is allowed.

      In this scenario:

      - The principal’s identity-based policy is granting PutObject unconditionally (no tag-based condition).
      - The bucket policy is trying to allow PutObject only if the "Team" tag on the object matches the principal’s "Team" tag. However, it does not contain an explicit Deny if the tags do not match; it simply does not “Allow” in that case.

      Because the bucket policy uses a conditional "Allow" without an explicit "Deny," it does not override the unconditional "Allow" from the identity-based policy. As there is no Deny statement in the bucket policy to block the request, the unconditional Allow from the identity policy wins.

    </details>

30. A security team is working on a solution that will use Amazon EventBridge to monitor new Amazon S3 objects. The solution will monitor for public access and for changes to any S3 bucket policy or setting that result in public access. The security team configures EventBridge to watch for specific API calls that are logged from AWS CloudTrail. EventBridge has an action to send an email notification through Amazon Simple Notification Service (Amazon SNS) to the security team immediately with details of the API call. Specifically, the security team wants EventBridge to watch for the s3:PutObjectAcl, s3:DeleteBucketPolicy, and s3:PutBucketPolicy API invocation logs from CloudTrail. While developing the solution in a single account, the security team discovers that the s3:PutObjectAcl API call does not invoke an EventBridge event However, the s3:DeleteBucketPolicy API call and the s3:PutBucketPolicy API call do invoke an event. The security team has enabled CloudTrail for AWS management events with a basic configuration in the AWS Region in which EventBridge is being tested. Verification of the EventBridge event pattern indicates that the pattern is set up correctly. The security team must implement a solution so that the s3:PutObjectAcl API call will invoke an EventBridge event. The solution must not generate false notifications. Which solution will meet these requirements?
    - [ ] A. Modify the EventBridge event pattern by selecting Amazon S3. Select All Events as the event type.
    - [ ] B. Modify the EventBridge event pattern by selecting Amazon S3. Select Bucket Level Operations as the event type.
    - [ ] C. Enable CloudTrail Insights to identify unusual API activity.
    - [ ] D. Enable CloudTrail to monitor data events for read and write operations to S3 buckets.

    <details>
       <summary>Answer</summary>

       D is correct -> The key point here is that s3:PutObjectAcl is a data event, whereas `s3:DeleteBucketPolicy` and `s3:PutBucketPolicy` are management events. By default, CloudTrail logs S3 management events (like bucket policy changes) without additional configuration, but it does not log data events (such as object ACL changes) unless you specifically enable them. To capture the `s3:PutObjectAcl` event so that EventBridge can react to it, you must enable CloudTrail data event logging for the relevant S3 bucket(s). Once the data event logging is enabled, CloudTrail will include s3:PutObjectAcl events in its logs. EventBridge rules can then match and forward these events to the security team’s SNS topic.

    </details>

31. A security engineer is asked to update an AWS CloudTrail log file prefix for an existing trail. When attempting to save the change in the CloudTrail console, the security engineer receives the following error message: "There is a problem with the bucket policy." What will enable the security engineer to save the change?
    - [ ] A. Create a new trail with the updated log file prefix, and then delete the original trail. Update the existing bucket policy in the Amazon S3 console with the new log file prefix, and then update the log file prefix in the CloudTrail console.
    - [ ] B. Update the existing bucket policy in the Amazon S3 console to allow the security engineer's principal to perform PutBucketPolicy, and then update the log file prefix in the CloudTrail console.
    - [ ] C. Update the existing bucket policy in the Amazon S3 console with the new log file prefix, and then update the log file prefix in the CloudTrail console.
    - [ ] D. Update the existing bucket policy in the Amazon S3 console to allow the security engineer's principal to perform GetBucketPolicy, and then update the log file prefix in the CloudTrail console.

    <details>
       <summary>Answer</summary>

       C is correct -> When you update a CloudTrail’s log file prefix, you must ensure that the updated prefix is permitted in the bucket policy. If the policy only grants permission to the old prefix, CloudTrail will fail to save the new prefix and display the “problem with the bucket policy” error message. Once you add the new prefix to the S3 bucket policy, you can successfully set the new prefix in the CloudTrail console.

    </details>

32. A company uses AWS Organizations. The company wants to implement short-term credentials for third-party AWS accounts to use to access accounts within the company's organization. Access is for the AWS Management Console and third-party software-as-a-service (SaaS) applications. Trust must be enhanced to prevent two external accounts from using the same credentials. The solution must require the least possible operational effort. Which solution will meet these requirements?
    - [ ] A. Use a bearer token authentication with OAuth or SAML to manage and share a central Amazon Cognito user pool across multiple Amazon API Gateway APIs.
    - [ ] B. Implement AWS IAM Identity Center (AWS Single Sign-On), and use an identity source of choice. Grant access to users and groups from other accounts by using permission sets that are assigned by account.
    - [ ] C. Create a unique IAM role for each external account. Create a trust policy Use AWS Secrets Manager to create a random external key.
    - [ ] D. Create a unique IAM role for each external account. Create a trust policy that includes a condition that uses the sts:ExternalId condition key.

    <details>
       <summary>Answer</summary>

       - A: Incorrect -> Useful for API authentication and potentially web or mobile apps, but does not integrate natively as easily with the AWS Management Console and does not inherently prevent multiple external entities from sharing credentials.
       - B: Correct ->
         - Short-term Credentials: AWS IAM Identity Center (formerly AWS Single Sign-On) issues temporary credentials whenever a user signs in. This satisfies the requirement for short-term credentials that can be used to access both AWS Management Console and third-party SaaS applications (via SAML or other federation protocols).
         - Prevent Credential Sharing: By using IAM Identity Center with an external identity provider or its native user store, each external user has a unique login. This ensures that no two external accounts share the same credentials, thereby enhancing trust and security.
         - Low Operational Overhead: AWS IAM Identity Center streamlines credential management across multiple AWS accounts in an organization: You do not have to create and manage separate IAM roles and trust policies for each external user. You can centrally manage user/group assignments (via permission sets) to different AWS accounts, greatly reducing ongoing administrative effort.
       - C: Incorrect -> Managing a unique IAM role and secrets per external account can become burdensome, and you still need a workflow to distribute and rotate these secrets effectively.
       - D: Incorrect ->  While using sts:ExternalId is a good best practice for cross-account assumption to prevent the confused deputy problem, creating and managing numerous roles for each external account is more complex and time-consuming compared to using AWS IAM Identity Center’s consolidated approach.

    </details>

33. A company is evaluating its security posture. In the past, the company has observed issues with specific hosts and host header combinations that affected the company's business. The company has configured AWS WAF web ACLs as an initial step to mitigate these issues. The company must create a log analysis solution for the AWS WAF web ACLs to monitor problematic activity. The company wants to process all the AWS WAF logs in a central location. The company must have the ability to filter out requests based on specific hosts. A security engineer starts to enable access logging for the AWS WAF web ACLs. What should the security engineer do next to meet these requirements with the MOST operational efficiency?
    - [ ] A. Specify Amazon Redshift as the destination for the access logs. Deploy the Amazon Athena Redshift connector. Use Athena to query the data from Amazon Redshift and to filter the logs by host.
    - [ ] B. Specify Amazon CloudWatch as the destination for the access logs. Use Amazon CloudWatch Logs Insights to design a query to filter the logs by host.
    - [ ] C. Specify Amazon CloudWatch as the destination for the access logs. Export the CloudWatch logs to an Amazon S3 bucket. Use Amazon Athena to query the logs and to filter the logs by host.
    - [ ] D. Specify Amazon CloudWatch as the destination for the access logs. Use Amazon Redshift Spectrum to query the logs and to filter the logs by host.

    <details>
       <summary>Answer</summary>

       B.

    </details>

34. A security engineer is trying to use Amazon EC2 Image Builder to create an image of an EC2 instance. The security engineer has configured the pipeline to send logs to an Amazon S3 bucket. When the security engineer runs the pipeline, the build fails with the following error: “AccessDenied: Access Denied status code: 403”. The security engineer must resolve the error by implementing a solution that complies with best practices for least privilege access. Which combination of steps will meet these requirements? (Choose two.)
    - [ ] A. Ensure that the following policies are attached to the IAM role that the security engineer is using: EC2InstanceProfileForImageBuilder, EC2InstanceProfileForImageBuilderECRContainerBuilds, and AmazonSSMManagedInstanceCore.
    - [ ] B. Ensure that the following policies are attached to the instance profile for the EC2 instance: EC2InstanceProfileForImageBuilder, EC2InstanceProfileForImageBuilderECRContainerBuilds, and AmazonSSMManagedInstanceCore.
    - [ ] C. Ensure that the AWSImageBuilderFullAccess policy is attached to the instance profile for the EC2 instance.
    - [ ] D. Ensure that the security engineer’s IAM role has the s3:PutObject permission for the S3 bucket.
    - [ ] E. Ensure that the instance profile for the EC2 instance has the s3:PutObject permission for the S3 bucket.

    <details>
       <summary>Answer</summary>

       The best practices solution is to attach the standard Image Builder policies to the instance profile (so the instance can access the needed services) and to give that instance profile the necessary permissions to write logs to Amazon S3. Therefore, the correct steps are:

       - Ensure that the following policies are attached to the instance profile for the EC2 instance:
         - EC2InstanceProfileForImageBuilder
         - EC2InstanceProfileForImageBuilderECRContainerBuilds (if building container images)
         - AmazonSSMManagedInstanceCore
       - Ensure that the instance profile for the EC2 instance has the s3:PutObject permission for the S3 bucket. Attaching these policies and permissions to the instan

    </details>

35. A security engineer must use AWS Key Management Service (AWS KMS) to design a key management solution for a set of Amazon Elastic Block Store (Amazon EBS) volumes that contain sensitive data. The solution needs to ensure that the key material automatically expires in 90 days. Which solution meets these criteria?
    - [ ] A. A customer managed key that uses customer provided key material
    - [ ] B. A customer managed key that uses AWS provided key material
    - [ ] C. An AWS managed key
    - [ ] D. Operating system encryption that uses GnuPG

    <details>
       <summary>Answer</summary>

       - A: Correct -> When you import your own key material into AWS KMS, you can specify an expiration time for that key material. After the expiration time, AWS KMS will automatically delete the key material and the key can no longer be used to encrypt or decrypt data. This is the only approach among the listed options that satisfies the requirement that the key material automatically expires in 90 days.
       - B: Incorrect -> Does not allow you to set an expiration period for AWS-provided key material.
       - C: Incorrect -> Also does not allow you to set an explicit expiration date. AWS managed keys do not expire automatically.
       - D: Incoorect -> This solution does not involve AWS Key Management Service for managing and expiring key material automatically.

    </details>

36. A company uses SAML federation to grant users access to AWS accounts. A company workload that is in an isolated AWS account runs on immutable infrastructure with no human access to Amazon EC2. The company requires a specialized user known as a break glass user to have access to the workload AWS account and instances in the case of SAML errors. A recent audit discovered that the company did not create the break glass user for the AWS account that contains the workload. The company must create the break glass user. The company must log any activities of the break glass user and send the logs to a security team. Which combination of solutions will meet these requirements? (Choose two.)
    - [ ] A. Create a local individual break glass IAM user for the security team. Create a trail in AWS CloudTrail that has Amazon CloudWatch Logs turned on. Use Amazon EventBridge to monitor local user activities.
    - [ ] B. Create a break glass EC2 key pair for the AWS account. Provide the key pair to the security team. Use AWS CloudTrail to monitor key pair activity. Send notifications to the security team by using Amazon Simple Notification Service (Amazon SNS).
    - [ ] C. Create a break glass IAM role for the account. Allow security team members to perform the AssumeRoleWithSAML operation. Create an AWS CloudTrail trail that has Amazon CloudWatch Logs turned on. Use Amazon EventBridge to monitor security team activities.
    - [ ] D. Create a local individual break glass IAM user on the operating system level of each workload instance. Configure unrestricted security groups on the instances to grant access to the break glass IAM users.
    - [ ] E. Configure AWS Systems Manager Session Manager for Amazon EC2. Configure an AWS CloudTrail filter based on Session Manager. Send the results to an Amazon Simple Notification Service (Amazon SNS) topic.

    <details>
       <summary>Answer</summary>

       - A:
         - A break glass user must not rely on the SAML identity provider—otherwise it would be unusable if the IdP or SAML flow fails.
         - Creating a local individual IAM user in the isolated AWS account ensures you always have a fallback login method.
         - Enabling AWS CloudTrail with CloudWatch Logs and EventBridge ensures that any API calls made by this IAM user are logged and can trigger alerts or notifications to the security team.
       - E:
         - Instead of distributing SSH keys (which are difficult to manage and audit), use AWS Systems Manager Session Manager.
         - Session Manager provides auditable, browser-based and CLI-based shell access to EC2 instances—no open SSH ports, no key pairs required.
         - Session Manager actions are logged in AWS CloudTrail; you can configure CloudTrail to route logs and alerts (e.g., via SNS) to the security team.

    </details>

37. A company stores images for a website in an Amazon S3 bucket. The company is using Amazon CloudFront to serve the images to the end users. The company recently discovered that the images are being accessed form countries where the company does not have a distribution license. Which actions should the company take to secure the images to limit their distribution? (Choose two.)
    - [ ] A. Update the S3 bucket policy to restrict access to a CloudFront origin access identity (OAI).
    - [ ] B. Update the website DNS record to use an Amazon Route 53 geolocation record deny list of countries where the company lacks a license.
    - [ ] C. Add a CloudFront geo restriction deny list of countries where the company lacks a license.
    - [ ] D. Update the S3 bucket policy with a deny list of countries where the company lacks a license.
    - [ ] E. Enable the Restrict Viewer Access option in CloudFront to create a deny list of countries where the company lacks a license.

    <details>
       <summary>Answer</summary>

     - A: Correct -> You should configure the S3 bucket to only allow requests originating from CloudFront. This prevents users from bypassing CloudFront and fetching images directly from S3.
     - B: Incorrect ->  Route 53 geolocation record does not effectively block access because users could still bypass the DNS setting (e.g., by hitting the CloudFront domain directly or changing DNS resolvers).
     - C: Correct -> CloudFront can block requests from specific countries, ensuring that users from those countries cannot access your content at all.
     - D: Incorrect -> S3 bucket policy with a country-deny list is not feasible with S3 alone, because S3 does not have native geolocation blocking, and IP-based blocking is impractical.
     - E: Incorrect -> Enable Restrict Viewer Access for CloudFront is typically for requiring signed URLs or signed cookies, not for geolocation enforcement.

    </details>

38. A company has deployed servers on Amazon EC2 instances in a VPC. External vendors access these servers over the internet. Recently, the company deployed a new application on EC2 instances in a new CIDR range. The company needs to make the application available to the vendors. A security engineer verified that the associated security groups and network ACLs are allowing the required ports in the inbound diction. However, the vendors cannot connect to the application. Which solution will provide the vendors access to the application?
    - [ ] A. Modify the security group that is associated with the EC2 instances to have the same outbound rules as inbound rules.
    - [ ] B. Modify the network ACL that is associated with the CIDR range to allow outbound traffic to ephemeral ports.
    - [ ] C. Modify the inbound rules on the internet gateway to allow the required ports.
    - [ ] D. Modify the network ACL that is associated with the CIDR range to have the same outbound rules as inbound rules.

    <details>
       <summary>Answer</summary>

     - B: Correct -> Ephemeral ports are temporary, high-numbered ports that get assigned automatically for the return leg of a connection. When a client connects to a server on a known “listener” port (for example, port 443 for HTTPS), the client’s source port is typically in the ephemeral range (commonly 1024–65535, though ranges can vary by operating system).

    </details>

39. An IAM user receives an Access Denied message when the user attempts to access objects in an Amazon S3 bucket. The user and the S3 bucket are in the same AWS account. The S3 bucket is configured to use server-side encryption with AWS KMS keys (SSE-KMS) to encrypt all of its objects at rest by using a customer managed key from the same AWS account. The S3 bucket has no bucket policy defined. The IAM user has been granted permissions through an IAM policy that allows the kms:Decrypt permission to the customer managed key. The IAM policy also allows the `s3:List*` and `s3:Get*` permissions for the S3 bucket and its objects. Which of the following is a possible reason that the IAM user cannot access the objects in the S3 bucket?
    - [ ] A. The IAM policy needs to allow the kms:DescribeKey permission.
    - [ ] B. The S3 bucket has been changed to use the AWS managed key to encrypt objects at rest.
    - [ ] C. An S3 bucket policy needs to be added to allow the IAM user to access the objects.
    - [ ] D. The KMS key policy has been edited to remove the ability for the AWS account to have full access to the key.

    <details>
       <summary>Answer</summary>

     - D: Correct -> Even though the IAM user has an IAM policy that grants `kms:Decrypt` and the necessary S3 permissions (`s3:Get*` and `s3:List*`), the KMS key policy ultimately governs who can use that key. If the key policy does not allow the IAM user (or the AWS account) to decrypt with that key, the user’s requests to access the object will fail with an Access Denied error.

    </details>

40. A security engineer wants to use Amazon Simple Notification Service (Amazon SNS) to send email alerts to a company's security team for Amazon GuardDuty findings that have a High severity level. The security engineer also wants to deliver these findings to a visualization tool for further examination. Which solution will meet these requirements?
    - [ ] A. Set up GuardDuty to send notifications to an Amazon CloudWatch alarm with two targets in CloudWatch. From CloudWatch, stream the findings through Amazon Kinesis Data Streams into an Amazon Open Search Service domain as the first target for delivery. Use Amazon QuickSight to visualize the findings. Use OpenSearch queries for further analysis. Deliver email alerts to the security team by configuring an SNS topic as a second target for the CloudWatch alarm. Use event pattern matching with an Amazon EventBridge event rule to send only High severity findings in the alerts.
    - [ ] B. Set up GuardDuty to send notifications to AWS CloudTrail with two targets in CloudTrail. From CloudTrail, stream the findings through Amazon Kinesis Data Firehose into an Amazon OpenSearch Service domain as the first target for delivery. Use OpenSearch Dashboards to visualize the findings. Use OpenSearch queries for further analysis. Deliver email alerts to the security team by configuring an SNS topic as a second target for CloudTrail. Use event pattern matching with a CloudTrail event rule to send only High severity findings in the alerts.
    - [ ] C. Set up GuardDuty to send notifications to Amazon EventBridge with two targets. From EventBridge, stream the findings through Amazon Kinesis Data Firehose into an Amazon OpenSearch Service domain as the first target for delivery. Use OpenSearch Dashboards to visualize the findings. Use OpenSearch queries for further analysis. Deliver email alerts to the security team by configuring an SNS topic as a second target for EventBridge. Use event pattern matching with an EventBridge event rule to send only High severity findings in the alerts.
    - [ ] D. Set up GuardDuty to send notifications to Amazon EventBridge with two targets. From EventBridge, stream the findings through Amazon Kinesis Data Streams into an Amazon OpenSearch Service domain as the first target for delivery. Use Amazon QuickSight to visualize the findings. Use OpenSearch queries for further analysis. Deliver email alerts to the security team by configuring an SNS topic as a second target for EventBridge. Use event pattern matching with an EventBridge event rule to send only High severity findings in the alerts.

    <details>
       <summary>Answer</summary>

     - C: Correct ->
       - Stream the findings to Amazon OpenSearch Service (via Kinesis Data Firehose), where you can use OpenSearch Dashboards to visualize the data and perform queries.
       - Send email alerts to an SNS topic for only the high-severity findings, by specifying an EventBridge event pattern that filters for GuardDuty findings with severity ≥ 7.0 (High).

    </details>

41. A security engineer needs to implement a write-once-read-many (WORM) model for data that a company will store in Amazon S3 buckets. The company uses the S3 Standard storage class for all of its S3 buckets. The security engineer must ensure that objects cannot be overwritten or deleted by any user, including the AWS account root user. Which solution will meet these requirements?
    - [ ] A. Create new S3 buckets with S3 Object Lock enabled in compliance mode. Place objects in the S3 buckets.
    - [ ] B. Use S3 Glacier Vault Lock to attach a Vault Lock policy to new S3 buckets. Wait 24 hours to complete the Vault Lock process. Place objects in the S3 buckets.
    - [ ] C. Create new S3 buckets with S3 Object Lock enabled in governance mode. Place objects in the S3 buckets.
    - [ ] D. Create new S3 buckets with S3 Object Lock enabled in governance mode. Add a legal hold to the S3 buckets. Place objects in the S3 buckets.

    <details>
       <summary>Answer</summary>

     - A: Correct ->
       - Governance mode allows certain users (for example, those with the required permissions or the root user) to delete or modify the retention settings of an object if they explicitly remove the object lock. Hence, governance mode does not meet the requirement of fully preventing all deletions or overwrites.
       - Compliance mode, on the other hand, prevents all users, including the root user, from removing or shortening the retention period or deleting an object before its retention period expires. This satisfies the WORM (write-once-read-many) requirement at the highest level of protection.

    </details>

42. A company needs complete encryption of the traffic between external users and an application. The company hosts the application on a fleet of Amazon EC2 instances that run in an Auto Scaling group behind an Application Load Balancer (ALB). How can a security engineer meet these requirements?
    - [ ] A. Create a new Amazon-issued certificate in AWS Secrets Manager. Export the certificate from Secrets Manager. Import the certificate into the ALB and the EC2 instances.
    - [ ] B. Create a new Amazon-issued certificate in AWS Certificate Manager (ACM). Associate the certificate with the ALExport the certificate from ACM. Install the certificate on the EC2 instances.
    - [ ] C. Import a new third-party certificate into AWS Identity and Access Management (IAM). Export the certificate from IAM. Associate the certificate with the ALB and the EC2 instances.
    - [ ] D. Import a new third-party certificate into AWS Certificate Manager (ACM). Associate the certificate with the ALB. Install the certificate on the EC2 instances.

    <details>
       <summary>Answer</summary>

     - A: Incorrect -> You cannot generate an Amazon-issued public certificate in Secrets Manager. ACM is the correct service for that.
     - B: Incorrect -> Public certificates from ACM are not exportable. You can only export private certificates from an ACM Private CA (which are not publicly trusted). Hence, you cannot install an Amazon-issued public certificate on your EC2 instances.
     - C: Incorrect -> Storing certificates in IAM is possible but considered a legacy approach. ACM is the recommended service for managing and deploying certificates to AWS Load Balancers and other services.
     - D: Correct

    </details>

43. A company hosts a public website on an Amazon EC2 instance. HTTPS traffic must be able to access the website. The company uses SSH for management of the web server. The website is on the subnet 10.0.1.0/24. The management subnet is 192.168.100.0/24. A security engineer must create a security group for the EC2 instance. Which combination of steps should the security engineer take to meet these requirements in the MOST secure manner? (Choose two.)
    - [ ] A. Allow port 22 from source 0.0.0.0/0.
    - [ ] B. Allow port 443 from source 0.0 0 0/0.
    - [ ] C. Allow port 22 from 192.168.100.0/24.
    - [ ] D. Allow port 22 from 10.0.1.0/24.
    - [ ] E. Allow port 443 from 10.0.1.0/24.

    <details>
       <summary>Answer</summary>

     - B: Correct -> This ensures that the website is publicly accessible over HTTPS.
     - C: Correct -> This ensures SSH management is only allowed from the private management subnet, which is more secure than allowing it from anywhere.

    </details>

44. A Systems Engineer is troubleshooting the connectivity of a test environment that includes a virtual security appliance deployed inline. In addition to using the virtual security appliance, the Development team wants to use security groups and network ACLs to accomplish various security requirements in the environment. What configuration is necessary to allow the virtual security appliance to route the traffic?
    - [ ] A. Disable network ACLs.
    - [ ] B. Configure the security appliance's elastic network interface for promiscuous mode.
    - [ ] C. Disable the Network Source/Destination check on the security appliance's elastic network interface
    - [ ] D. Place the security appliance in the public subnet with the internet gateway

    <details>
       <summary>Answer</summary>

     C is correct. In AWS, any EC2 instance that needs to act as a router or forward traffic on behalf of other machines must have this check disabled. By default, EC2 instances discard traffic where the source or destination does not match their own IP addresses. Disabling Source/Destination check ensures the traffic can flow through the virtual security appliance normally.

    </details>

45. A company is using AWS WAF to protect a customized public API service that is based on Amazon EC instances. The API uses an Application Load Balancer. The AWS WAF web ACL is configured with an AWS Managed Rules rule group. After a software upgrade to the API and the client application, some types of requests are no longer working and are causing application stability issues. A security engineer discovers that AWS WAF logging is not turned on for the web ACL. The security engineer needs to immediately return the application to service, resolve the issue, and ensure that logging is not turned off in the future. The security engineer turns on logging for the web ACL and specifies Amazon CloudWatch Logs as the destination. Which additional set of steps should the security engineer take to meet the requirements?
    - [ ] A. Edit the rules in the web ACL to include rules with Count and Challenge actions. Review the logs to determine which rule is blocking the request. Modify the AWS WAF resource policy so that AWS WAF administrators cannot remove the logging configuration for any AWS WAF web ACLs.
    - [ ] B. Edit the rules in the web ACL to include rules with Count actions. Review the logs to determine which rule is blocking the request. Modify the AWS WAF resource policy so that AWS WAF administrators cannot remove the logging configuration for any AWS WAF web ACLs.
    - [ ] C. Edit the rules in the web ACL to include rules with Count and Challenge actions. Review the logs to determine which rule is blocking the request. Modify the IAM policy of all AWS WAF administrators so that they cannot remove the logging configuration for any AWS WAF web ACLs.
    - [ ] D. Edit the rules in the web ACL to include rules with Count actions. Review the logs to determine which rule is blocking the request. Modify the IAM policy of all AWS WAF administrators so that they cannot remove the logging configuration for any AWS WAF web ACLs.

    <details>
       <summary>Answer</summary>

     B is correct. The most straightforward way to address the immediate problem (restore service) is to switch the relevant rules in the AWS WAF web ACL from Block to Count actions. This way, the requests will no longer be blocked (restoring service), and you can still observe which rules would have been triggered by reviewing the WAF logs. Then, to ensure logging is not disabled in the future, you can attach or modify the AWS WAF resource policy to prevent administrators from changing or removing the logging configuration.

    </details>

46. A security engineer is creating an AWS Lambda function. The Lambda function needs to use a role that is named LambdaAuditRole to assume a role that is named AcmeAuditFactoryRole in a different AWS account. When the code is processed, the following error message appears: "An error occurred (AccessDenied) when calling the AssumeRole operation." Which combination of steps should the security engineer take to resolve this error? (Choose two.)
    - [ ] A. Ensure that LambdaAuditRole has the sts:AssumeRole permission for AcmeAuditFactoryRole.
    - [ ] B. Ensure that LambdaAuditRole has the AWSLambdaBasicExecutionRole managed policy attached.
    - [ ] C. Ensure that the trust policy for AcmeAuditFactoryRole allows the sts:AssumeRole action from LambdaAuditRole.
    - [ ] D. Ensure that the trust policy for LambdaAuditRole allows the sts:AssumeRole action from the lambda.amazonaws.com service.
    - [ ] E. Ensure that the sts:AssumeRole API call is being issued to the us-east-1 Region endpoint.

    <details>
       <summary>Answer</summary>

       - A: Ensure that the role executing the assume (LambdaAuditRole) has sts:AssumeRole permissions for the target role (AcmeAuditFactoryRole). In other words, LambdaAuditRole must include an IAM policy statement that allows sts:AssumeRole on the ARN of AcmeAuditFactoryRole.
       - C: Ensure that the trust policy of AcmeAuditFactoryRole trusts LambdaAuditRole. The trust policy attached to AcmeAuditFactoryRole must list LambdaAuditRole as a trusted principal and allow the sts:AssumeRole action.
       - 有两个工厂：工厂A 和 工厂B。
       - 工厂A 中有一台自动生产机器人（对应 AWS Lambda），它平时穿着一套“LambdaAuditRole”的工作服（对应在工厂A中的Role）。现在，这台机器人需要到工厂B里去“临时客串”另一个岗位，名为 “AcmeAuditFactoryRole” 的工作服（对应在工厂B中的Role）。但当它想从工厂B的仓库领用这套“工作服”（也就是调用 sts:AssumeRole）时，被门卫拦下，报错：“AccessDenied”，无法进去。
       - 这时我们就要想：为什么机器人在工厂B拿不到“AcmeAuditFactoryRole”？要让外来人员穿上工厂B的工作服，需要满足两方面的条件：
         - 它自己（工厂A）有没有允许它去“请求”那套工作服？（源头权限）
         - 工厂B 相不相信它，让不让它穿这套工作服？（目标信任）
       - 在工厂A的“LambdaAuditRole”上，需要一条能够对工厂B中对应的“AcmeAuditFactoryRole”执行 sts:AssumeRole 的权限。
       - 在工厂B里让“门卫”相信，工厂A的这台机器人可以来穿我们的工作服。

    </details>

47. A company has AWS accounts in an organization in AWS Organizations. The organization includes a dedicated security account. All AWS account activity across all member accounts must be logged and reported to the dedicated security account. The company must retain all the activity logs in a secure storage location within the dedicated security account for 2 years. No changes or deletions of the logs are allowed. Which combination of steps will meet these requirements with the LEAST operational overhead? (Choose two.)
    - [ ] A. In the dedicated security account, create an Amazon S3 bucket. Configure S3 Object Lock in compliance mode and a retention period of 2 years on the S3 bucket. Set the bucket policy to allow the organization's management account to write to the S3 bucket.
    - [ ] B. In the dedicated security account, create an Amazon S3 bucket. Configure S3 Object Lock in compliance mode and a retention period of 2 years on the S3 bucket. Set the bucket policy to allow the organization's member accounts to write to the S3 bucket.
    - [ ] C. In the dedicated security account, create an Amazon S3 bucket that has an S3 Lifecycle configuration that expires objects after 2 years. Set the bucket policy to allow the organization's member accounts to write to the S3 bucket.
    - [ ] D. Create an AWS CloudTrail trail for the organization. Configure logs to be delivered to the logging Amazon S3 bucket in the dedicated security account.
    - [ ] E. Turn on AWS CloudTrail in each account. Configure logs to be delivered to an Amazon S3 bucket that is created in the organization's management account. Forward the logs to the S3 bucket in the dedicated security account by using AWS Lambda and Amazon Kinesis Data Firehose.

    <details>
       <summary>Answer</summary>

       - A: Correct -> This ensures that all logs are stored securely for 2 years with no changes or deletions allowed due to S3 Object Lock in compliance mode. Allowing the management account to write simplifies access control while ensuring logs are centrally stored.
       - B: Incorrect -> It’s better to let the organization’s management account control this centrally instead of managing policies for each member account.
       - C: Incorrect -> S3 Lifecycle does not prevent deletion or modification of logs, whereas S3 Object Lock in compliance mode ensures logs cannot be altered.
       - D: Correct -> An organization trail captures all AWS account activity across all member accounts with a single CloudTrail setup, significantly reducing operational overhead. Logs are automatically delivered to the security account’s S3 bucket.
       - E: Incorrect -> This introduces unnecessary operational complexity and costs. A single organization trail (Option D) already consolidates logs efficiently.

    </details>

48. An AWS account administrator created an IAM group and applied the following managed policy to require that each individual user authenticate using multi-factor authentication, After implementing the policy, the administrator receives reports that users are unable to perform Amazon EC2 commands using the AWS CLI. What should the administrator do to resolve this problem while still enforcing multi-factor authentication?

    ```json
    {
      "Version": "2012-10-17",
      "Statement": [
         {
            "Effect": "Allow",
            "Action": "ec2:*",
            "Resource": "*"
         },
         {
            "Sid": "BlockAnyAccessUnlessSignedInWithMFA",
            "Effect": "Deny",
            "Action": "ec2:*",
            "Resource": "*",
            "Condition": {
               "BoolIfExists": {
                  "aws:MultiFctorAuthPresent": false
               }
            }
         }
      ]
    }
    ```

    - [ ] A. Change the value of aws:MultiFactorAuthPresent to true.
    - [ ] B. Instruct users to run the aws sts get-session-token CLI command and pass the multi-factor authentication --serial-number and --token-code parameters. Use these resulting values to make API/CLI calls.
    - [ ] C. Implement federated API/CLI access using SAML 2.0, then configure the identity provider to enforce multi-factor authentication.
    - [ ] D. Create a role and enforce multi-factor authentication in the role trust policy. Instruct users to run the sts assume-role CLI command and pass --serial-number and --token-code parameters. Store the resulting values in environment variables. Add sts:AssumeRole to NotAction in the policy.

    <details>
       <summary>Answer</summary>

       The policy has two statements the "Deny" statement overrides the "Allow" when users authenticate without MFA. When a user logs in via the AWS CLI using long-term IAM credentials, the MFA condition (aws:MultiFactorAuthPresent) is not automatically included, which results in denial. Users must obtain temporary credentials with MFA enabled. The AWS CLI allows users to authenticate with MFA using the aws sts get-session-token command: `aws sts get-session-token --serial-number arn:aws:iam::ACCOUNT-ID:mfa/DEVICE-NAME --token-code MFA-CODE`

    </details>

49. A company has AWS accounts that are in an organization in AWS Organizations. An Amazon S3 bucket in one of the accounts is publicly accessible. A security engineer must change the configuration so that the S3 bucket is no longer publicly accessible. The security engineer also must ensure that the S3 bucket cannot be made publicly accessible in the future. Which solution will meet these requirements?
    - [ ] A. Configure the S3 bucket to use an AWS Key Management Service (AWS KMS) key. Encrypt all objects in the S3 bucket by creating a bucket policy that enforces encryption. Configure an SCP to deny the s3:GetObject action for the OU that contains the AWS account.
    - [ ] B. Enable the PublicAccessBlock configuration on the S3 bucket. Configure an SCP to deny the s3:GetObject action for the OU that contains the AWS account.
    - [ ] C. Enable the PublicAccessBlock configuration on the S3 bucket. Configure an SCP to deny the s3:PutPublicAccessBlock action for the OU that contains the AWS account.
    - [ ] D. Configure the S3 bucket to use S3 Object Lock in governance mode. Configure an SCP to deny the s3:PutPublicAccessBlock action for the OU that contains the AWS account.

    <details>
       <summary>Answer</summary>

      B is correct. AWS provides S3 Block Public Access settings that allow you to block public access to the bucket and its objects. Enabling PublicAccessBlock ensures that public access is blocked, even if ACLs or bucket policies allow it. A Service Control Policy (SCP) can be applied at the AWS Organizations level to deny any attempt to modify the PublicAccessBlock settings `s3:PutPublicAccessBlock`. This ensures that even if someone with the right permissions tries to disable the public access block, they will be denied.

    </details>

50. A company uses SAML federation with AWS Identity and Access Management (IAM) to provide internal users with SSO for their AWS accounts. The company's identity provider certificate was rotated as part of its normal lifecycle. Shortly after, users started receiving the following error when attempting to log in: "Error: Response Signature Invalid (Service: AWSSecurityTokenService; Status Code: 400; Error Code: InvalidIdentityToken)" A security engineer needs to address the immediate issue and ensure that it will not occur again. Which combination of steps should the security engineer take to accomplish this? (Choose two.)
    - [ ] A. Download a new copy of the SAML metadata file from the identity provider. Create a new IAM identity provider entity. Upload the new metadata file to the new IAM identity provider entity.
    - [ ] B. During the next certificate rotation period and before the current certificate expires, add a new certificate as the secondary to the identity provider. Generate a new metadata file and upload it to the IAM identity provider entity. Perform automated or manual rotation of the certificate when required.
    - [ ] C. Download a new copy of the SAML metadata file from the identity provider. Upload the new metadata to the IAM identity provider entity configured for the SAML integration in question.
    - [ ] D. During the next certificate rotation period and before the current certificate expires, add a new certificate as the secondary to the identity provider. Generate a new copy of the metadata file and create a new IAM identity provider entity. Upload the metadata file to the new IAM identity provider entity. Perform automated or manual rotation of the certificate when required.
    - [ ] E. Download a new copy of the SAML metadata file from the identity provider. Create a new IAM identity provider entity. Upload the new metadata file to the new IAM identity provider entity. Update the identity provider configurations to pass a new IAM identity provider entity name in the SAML assertion.

    <details>
       <summary>Answer</summary>

      The error "Response Signature Invalid (Service: AWSSecurityTokenService; Status Code: 400; Error Code: InvalidIdentityToken)" indicates that AWS IAM is rejecting the SAML response due to an invalid or mismatched signature. This typically happens when the identity provider (IdP) certificate is rotated, but the updated SAML metadata containing the new certificate is not uploaded to AWS IAM.

      - C: Since the identity provider certificate was rotated, the SAML metadata file that includes the updated certificate must be re-uploaded to AWS IAM.
      - B: To avoid a repeat of this issue, the best practice is to ensure seamless certificate rotation by configuring a secondary certificate before the existing certificate expires.

    </details>

51. A company is implementing a new application in a new AWS account. A VPC and subnets have been created for the application. The application has been peered to an existing VPC in another account in the same AWS Region for database access Amazon EC2 instances will regularly be created and terminated in the application VPC, but only some of them will need access to the databases in the peered VPC over TCP port 1521. A security engineer must ensure that only the EC2 instances that need access to the databases can access them through the network. How can the security engineer implement this solution?
    - [ ] A. Create a new security group in the database VPC and create an inbound rule that allows all traffic from the IP address range of the application VPC. Add a new network ACL rule on the database subnets. Configure the rule to TCP port 1521 from the IP address range of the application VPC. Attach the new security group to the database instances that the application instances need to access.
    - [ ] B. Create a new security group in the application VPC with an inbound rule that allows the IP address range of the database VPC over TCP port 1521. Create a new security group in the database VPC with an inbound rule that allows the IP address range of the application VPC over port 1521. Attach the new security group to the database instances and the application instances that need database access.
    - [ ] C. Create a new security group in the application VPC with no inbound rules. Create a new security group in the database VPC with an inbound rule that allows TCP port 1521 from the new application security group in the application VPAttach the application security group to the application instances that need database access and attach the database security group to the database instances.
    - [ ] D. Create a new security group in the application VPC with an inbound rule that allows the IP address range of the database VPC over TCP port 1521. Add a new network ACL rule on the database subnets. Configure the rule to allow all traffic from the IP address range of the application VPC. Attach the new security group to the application instances that need database access.

    <details>
       <summary>Answer</summary>

      - A: Incorrect -> Allows all traffic from the entire application VPC IP range, which is too broad and not recommended for fine-grained security. Also, unnecessary use of NACLs.
      - B: Incorrect -> Uses IP ranges instead of security group references, making it difficult to manage dynamically created EC2 instances.
      - C: Correct.
      - D: Incorrect -> Similar to A, allowing all traffic from the application VPC IP range is not a best practice, and modifying network ACLs is unnecessary.

    </details>

52. An Amazon EC2 Auto Scaling group launches Amazon Linux EC2 instances and installs the Amazon CloudWatch agent to publish logs to Amazon CloudWatch Logs. The EC2 instances launch with an IAM role that has an IAM policy attached. The policy provides access to publish custom metrics to CloudWatch. The EC2 instances run in a private subnet inside a VPC. The VPC provides access to the internet for private subnets through a NAT gateway. A security engineer notices that no logs are being published to CloudWatch Logs for the EC2 instances that the Auto Scaling group launches. The security engineer validates that the CloudWatch Logs agent is running and is configured properly on the EC2 instances. In addition, the security engineer validates that network communications are working properly to AWS services. What can the security engineer do to ensure that the logs are published to CloudWatch Logs?
    - [ ] A. Configure the IAM policy in use by the IAM role to have access to the required cloudwatch: API actions that will publish logs.
    - [ ] B. Adjust the Amazon EC2 Auto Scaling service-linked role to have permissions to write to CloudWatch Logs.
    - [ ] C. Configure the IAM policy in use by the IAM role to have access to the required AWS logs: API actions that will publish logs.
    - [ ] D. Add an interface VPC endpoint to provide a route to CloudWatch Logs.

    <details>
       <summary>Answer</summary>

      - A: Correct.
      - B: Incorrect -> The Auto Scaling service-linked role is not responsible for log publishing. The IAM role attached to the EC2 instances handles that.
      - C: Incorrect -> There is no AWS `logs:` API action; the correct namespace is `cloudwatch:`, making A the correct choice.
      - D: Incorrect -> Since the VPC already has internet access via a NAT gateway, there is no need to add a VPC endpoint.

    </details>

53. A company hosts an application on Amazon EC2 that is subject to specific rules for regulatory compliance. One rule states that traffic to and from the workload must be inspected for network-level attacks. This involves inspecting the whole packet. To comply with this regulatory rule, a security engineer must install intrusion detection software on a c5n.4xlarge EC2 instance. The engineer must then configure the software to monitor traffic to and from the application instances. What should the security engineer do next?
    - [ ] A. Place the network interface in promiscuous mode to capture the traffic
    - [ ] B. Configure VPC Flow Logs to send traffic to the monitoring EC2 instance using a Network Load Balancer.
    - [ ] C. Configure VPC traffic mirroring to send traffic to the monitoring EC2 instance using a Network Load Balancer.
    - [ ] D. Use Amazon Inspector to detect network-level attacks and trigger an AWS Lambda function to send the suspicious packets to the EC2 instance.

    <details>
       <summary>Answer</summary>

      - A: Incorrect -> AWS does not allow placing Elastic Network Interfaces (ENIs) into promiscuous mode.
      - B: Incorrect -> VPC Flow Logs (option B) only capture metadata (not the full packet), making it insufficient for deep packet inspection.
      - C: Correct -> VPC Traffic Mirroring allows you to capture full packets from network interfaces and send them to a target (such as an EC2 instance running intrusion detection software). A Network Load Balancer (NLB) can be used to distribute mirrored traffic to multiple monitoring instances for scalability.
      - D: Incorrect -> It is primarily used for vulnerability management, not deep network traffic inspection.

    </details>

54. A company has a VPC that has no internet access and has the private DNS hostnames option enabled. An Amazon Aurora database is running inside the VPC. A security engineer wants to use AWS Secrets Manager to automatically rotate the credentials for the Aurora database. The security engineer configures the Secrets Manager default AWS Lambda rotation function to run inside the same VPC that the Aurora database uses. However, the security engineer determines that the password cannot be rotated properly because the Lambda function cannot communicate with the Secrets Manager endpoint. What is the MOST secure way that the security engineer can give the Lambda function the ability to communicate with the Secrets Manager endpoint?
    - [ ] A. Add a NAT gateway to the VPC to allow access to the Secrets Manager endpoint.
    - [ ] B. Add a gateway VPC endpoint to the VPC to allow access to the Secrets Manager endpoint.
    - [ ] C. Add an interface VPC endpoint to the VPC to allow access to the Secrets Manager endpoint.
    - [ ] D. Add an internet gateway for the VPC to allow access to the Secrets Manager endpoint.

    <details>
       <summary>Answer</summary>

      - A: Incorrect -> A NAT gateway allows outbound internet access for resources in a private subnet, but this is unnecessary and less secure than using an interface VPC endpoint.
      - B: Incorrect -> Gateway endpoints only support Amazon S3 and DynamoDB, not AWS Secrets Manager.
      - C: Correct -> Interface endpoints use AWS PrivateLink to establish a private connection between the VPC and the AWS service (Secrets Manager in this case).
      - D: Incorrect -> An internet gateway would expose the VPC to the public internet, reducing security. The Lambda function does not need internet access, just private access to Secrets Manager.

    </details>

55. A company has two AWS accounts: Account A and Account B. Each account has a VPC. An application that runs in the VPC in Account A needs to write to an Amazon S3 bucket in Account B. The application in Account A already has permission to write to the S3 bucket in Account B. The application and the S3 bucket are in the same AWS Region. The company cannot send network traffic over the public internet. Which solution will meet these requirements?
    - [ ] A. In both accounts, create a transit gateway and VPC attachments in a subnet in each Availability Zone. Update the VPC route tables.
    - [ ] B. Deploy a software VPN appliance in Account A. Create a VPN connection between the software VPN appliance and a virtual private gateway in Account B.
    - [ ] C. Create a VPC peering connection between the VPC in Account A and the VPC in Account B. Update the VPC route tables, network ACLs, and security groups to allow network traffic between the peered IP ranges
    - [ ] D. In Account A, create a gateway VPC endpoint for Amazon S3. Update the VPC route table in Account A.

    <details>
       <summary>Answer</summary>

      - A: Incorrect -> A transit gateway is mainly used for connecting multiple VPCs or hybrid networks.
      - B: Incorrect -> A VPN is used for connecting on-premises to AWS or interconnecting VPCs across AWS accounts. It does not provide direct access to S3 without routing through an internet gateway or another AWS service.
      - C: Incorrect -> S3 is a regional AWS service and does not reside inside a VPC, so VPC peering does not help with direct S3 access.
      - D: Correct -> A gateway VPC endpoint allows private communication between resources in a VPC and Amazon S3, without requiring internet access.

    </details>

56. An online media company has an application that customers use to watch events around the world. The application is hosted on a fleet of Amazon EC2 instances that run Amazon Linux 2. The company uses AWS Systems Manager to manage the EC2 instances. The company applies patches and application updates by using the AWS-AmazonLinux2DefaultPatchBaseline patching baseline in Systems Manager Patch Manager. The company is concerned about potential attacks on the application during the week of an upcoming event. The company needs a solution that can immediately deploy patches to all the EC2 instances in response to a security incident or vulnerability. The solution also must provide centralized evidence that the patches were applied successfully. Which combination of steps will meet these requirements? (Choose two.)
    - [ ] A. Create a new patching baseline in Patch Manager. Specify Amazon Linux 2 as the product. Specify Security as the classification. Set the automatic approval for patches to 0 days. Ensure that the new patching baseline is the designated default for Amazon Linux 2.
    - [ ] B. Use the Patch Now option with the scan and install operation in the Patch Manager console to apply patches against the baseline to all nodes. Specify an Amazon S3 bucket as the patching log storage option.
    - [ ] C. Use the Clone function of Patch Manager to create a copy of the AWS-AmazonLmux2DefaultPatchBaseline built-in baseline. Set the automatic approval for patches to 1 day.
    - [ ] D. Create a patch policy that patches all managed nodes and sends a patch operation log output to an Amazon S3 bucket. Use a custom scan schedule to set Patch Manager to check every hour for new patches. Assign the baseline to the patch policy.
    - [ ] E. Use Systems Manager Application Manager to inspect the package versions that were installed on the EC2 instances. Additionally use Application Manager to validate that the patches were correctly installed.

    <details>
       <summary>Answer</summary>

      - A: Correct -> This ensures that all security-related patches are applied immediately (0-day approval). Designating it as the default baseline ensures all future patch operations apply the security patches.
      - B: Correct -> Patch Now allows for immediate patch deployment instead of waiting for scheduled patch cycles. Storing logs in Amazon S3 ensures centralized evidence and auditability.
      - C: Incorrect -> This still introduces a 1-day delay, which does not meet the requirement for immediate patching.
      - D: Incorrect -> This provides frequent checks, but waiting for an hourly schedule does not ensure immediate application of patches.
      - E: Incorrect -> Application Manager helps with verification, but it does not deploy patches. The company needs immediate deployment, not just validation.

    </details>

57. A developer operations team uses AWS Identity and Access Management (IAM) to manage user permissions. The team created an Amazon EC2 instance profile role that uses an AWS managed ReadOnlyAccess policy. When an application that is running on Amazon EC2 tries to read a file from an encrypted Amazon S3 bucket, the application receives an AccessDenied error. The team administrator has verified that the S3 bucket policy allows everyone in the account to access the S3 bucket. There is no object ACL that is attached to the file. What should the administrator do to fix the IAM access issue?
    - [ ] A. Edit the ReadOnlyAccess policy to add kms:Decrypt actions.
    - [ ] B. Add the EC2 IAM role as the authorized Principal to the S3 bucket policy.
    - [ ] C. Attach an inline policy with kms:Decrypt permissions to the IAM role.
    - [ ] D. Attach an inline policy with S3:* permissions to the IAM role.

    <details>
       <summary>Answer</summary>

      The issue here is that the Amazon S3 bucket is encrypted, and the application running on the EC2 instance lacks permissions to decrypt the file. The ReadOnlyAccess policy does not include KMS decryption permissions, which are required to read objects encrypted with AWS Key Management Service (KMS).
      - A: Incorrect -> AWS-managed policies cannot be edited.
      - B: Incorrect -> The bucket policy already allows access to everyone in the account, so adding the IAM role as a principal won’t solve the KMS decryption issue.
      - C: Correct -> The application needs `kms:Decrypt` permissions to decrypt the file. This can be done by attaching an inline policy or a separate managed policy granting `kms:Decrypt` access to the KMS key used for encryption.
      - D: Incorrect -> While this would grant broader S3 access, it doesn’t resolve the KMS decryption issue, which is the root cause of the AccessDenied error.

    </details>

58. A company in France uses Amazon Cognito with the Cognito Hosted UI as an identity broker for sign-in and sign-up processes. The company is marketing an application and expects that all the application's users will come from France. When the company launches the application, the company's security team observes fraudulent sign-ups for the application. Most of the fraudulent registrations are from users outside of France. The security team needs a solution to perform custom validation at sign-up. Based on the results of the validation, the solution must accept or deny the registration request. Which combination of steps will meet these requirements? (Choose two.)
    - [ ] A. Create a pre sign-up AWS Lambda trigger. Associate the Amazon Cognito function with the Amazon Cognito user pool.
    - [ ] B. Use a geographic match rule statement to configure an AWS WAF web ACL. Associate the web ACL with the Amazon Cognito user pool.
    - [ ] C. Configure an app client for the application's Amazon Cognito user pool. Use the app client ID to validate the requests in the hosted UI.
    - [ ] D. Update the application's Amazon Cognito user pool to configure a geographic restriction setting.
    - [ ] E. Use Amazon Cognito to configure a social identity provider (IdP) to validate the requests on the hosted UI.

    <details>
       <summary>Answer</summary>

      - A: Correct -> A pre sign-up Lambda function can validate the country of the user by checking the IP address or requiring specific attributes, and then reject sign-ups from users outside of France.
      - B: Correct -> AWS WAF (Web Application Firewall) can be used to block requests based on geographic location (GeoMatch rule).
      - C: Incorrect -> The app client ID is not used for validation of sign-up locations. It is primarily used for authentication and authorization, not for rejecting fraudulent registrations.
      - D: Incorrect -> Amazon Cognito does not have built-in geographic restriction settings.
      - E: Incorrect -> While social identity providers (like Google, Facebook) offer user authentication, they do not validate users based on geographic location.

    </details>

59. A security engineer is configuring AWS Config for an AWS account that uses a new 1AM entity. When the security engineer tries to configure AWS Config rules and automatic remediation options, errors occur. In the AWS CloudTrail logs, the security engineer sees the following error message: "Insufficient delivery policy to s3 bucket: DOC-EXAMPLE-BUCKET, unable to write to bucket, provided s3 key prefix is 'null'." Which combination of steps should the security engineer take to remediate this issue? (Choose two.)
    - [ ] A. Check the Amazon S3 bucket policy. Verify that the policy allows the `config.amazonaws.com` service to write to the target bucket.
    - [ ] B. Verify that the IAM entity has the permissions necessary to perform the `s3:GetBucketAcl` and `s3:PutObject*` operations to write to the target bucket.
    - [ ] C. Verify that the Amazon S3 bucket policy has the permissions necessary to perform the s3:GetBucketAcl and `s3:PutObject*` operations to write to the target bucket.
    - [ ] D. Check the policy that is associated with the IAM entity. Verify that the policy allows the `config.amazonaws.com` service to write to the target bucket.
    - [ ] E. Verify that the AWS Config service role has permissions to invoke the `BatchGetResourceConfig` action instead of the `GetResourceConfigHistory` action and `s3:PutObject*` operation.

    <details>
       <summary>Answer</summary>

      - A: Correct -> AWS Config needs explicit permissions to write to the designated S3 bucket. The S3 bucket policy should allow AWS Config (config.amazonaws.com) to perform s3:PutObject operations.
      - B: Correct -> The IAM entity (user, role, or service role) must have permissions to access the S3 bucket. It should have at least `s3:GetBucketAcl` to check the bucket's access control list and `s3:PutObject*` to store AWS Config logs.
      - C: Incorrect -> The S3 bucket policy does not need to perform s3:GetBucketAcl itself; the IAM entity (such as the AWS Config service role) needs those permissions.
      - D: Incorrect -> The AWS Config service does not directly write to S3 as an IAM entity. Instead, it assumes a service role with the appropriate permissions.
      - E: Incorrect -> `BatchGetResourceConfig` and `GetResourceConfigHistory` are related to AWS Config’s ability to retrieve configuration details, but they are not related to writing configuration logs to S3.

    </details>

60. A company is worried about potential DDoS attacks. The company has a web application that runs on Amazon EC2 instances. The application uses Amazon S3 to serve static content such as images and videos. A security engineer must create a resilient architecture that can withstand DDoS attacks. Which solution will meet these requirements MOST cost-effectively?
    - [ ] A. Create an Amazon CloudWatch alarm that invokes an AWS Lambda function when an EC2 instance’s CPU utilization reaches 90%. Program the Lambda function to update security groups that are attached to the EC2 instance to deny inbound ports 80 and 443.
    - [ ] B. Put the EC2 instances into an Auto Scaling group behind an Elastic Load Balancing (ELB) load balancer. Use Amazon CioudFront with Amazon S3 as an origin.
    - [ ] C. Set up a warm standby disaster recovery (DR) environment. Fail over to the warm standby DR environment if a DDoS attack is detected on the application.
    - [ ] D. Subscribe to AWS Shield Advanced. Configure permissions to allow the Shield Response Team to manage resources on the company's behalf during a DDoS event.

    <details>
       <summary>Answer</summary>

      - A: Incorrect -> Blocking ports 80 and 443 during a DDoS attack effectively takes the application offline, making it unavailable to legitimate users. This is not a good approach for high availability.
      - B: Correct
      - C: Incorrect -> Setting up a warm standby is expensive and primarily used for disaster recovery, not for mitigating DDoS. Also, it doesn’t prevent attacks, only provides failover.
      - D: Icorrect -> Shield Advanced offers strong DDoS protection but is costly (~$3,000/month). If cost-effectiveness is a priority, CloudFront with built-in AWS Shield Standard is a better option.

    </details>

61. A company has AWS accounts in an organization in AWS Organizations. The company needs to install a corporate software package on all Amazon EC2 instances for all the accounts in the organization. A central account provides base AMIs for the EC2 instances. The company uses AWS Systems Manager for software inventory and patching operations. A security engineer must implement a solution that detects EC2 instances ttjat do not have the required software. The solution also must automatically install the software if the software is not present. Which solution will meet these requirements?
    - [ ] A. Provide new AMIs that have the required software pre-installed. Apply a tag to the AMIs to indicate that the AMIs have the required software. Configure an SCP that allows new EC2 instances to be launched only if the instances have the tagged AMIs. Tag all existing EC2 instances.
    - [ ] B. Configure a custom patch baseline in Systems Manager Patch Manager. Add the package name for the required software to the approved packages list. Associate the new patch baseline with all EC2 instances. Set up a maintenance window for software deployment.
    - [ ] C. Centrally enable AWS Config. Set up the ec2-managedinstance-applications-required AWS Config rule for all accounts Create an Amazon EventBridge rule that reacts to AWS Config events. Configure the EventBridge rule to invoke an AWS Lambda function that uses Systems Manager Run Command to install the required software.
    - [ ] D. Create a new Systems Manager Distributor package for the required software. Specify the download location. Select all EC2 instances in the different accounts. Install the software by using Systems Manager Run Command.

    <details>
       <summary>Answer</summary>

      - A: Incorrect -> While tagging AMIs ensures new instances use the correct base image, it does not detect or fix software compliance on existing instances. SCPs (Service Control Policies) can restrict actions but cannot enforce or install software.
      - B: Incorrect -> Patch Manager is mainly used for OS patching rather than for installing arbitrary software packages. It does not continuously enforce software presence or automatically install missing software when a new instance is launched.
      - C: Correct -> The `ec2-managedinstance-applications-required` AWS Config rule ensures that specific software packages are installed on EC2 instances. The EventBridge rule invokes an AWS Lambda function that uses AWS Systems Manager Run Command to install the missing software on the non-compliant instance. AWS Config can be enabled centrally across all accounts in the AWS Organization using AWS Organizations integration.
      - D: Icorrect -> This solution installs the software but lacks automatic enforcement when a new instance is launched or when an instance becomes non-compliant.

    </details>

62. A company is investigating controls to protect sensitive data. The company uses Amazon Simple Notification Service (Amazon SNS) topics to publish messages from application components to custom logging services. The company is concerned that an application component might publish sensitive data that will be accidentally exposed in transaction logs and debug logs. Which solution will protect the sensitive data in these messages from accidental exposure?
    - [ ] A. Use Amazon Made to scan the SNS topics for sensitive data elements in the SNS messages. Create an AWS Lambda function that masks sensitive data inside the messages when Macie records a new finding.
    - [ ] B. Configure an inbound message data protection policy. In the policy, include the De-identify operation to mask the sensitive data inside the messages. Apply the policy to the SNS topics.
    - [ ] C. Configure the SNS topics with an AWS Key Management Service (AWS KMS) customer managed key to encrypt the data elements inside the messages. Grant permissions to all message publisher IAM roles to allow access to the key to encrypt data.
    - [ ] D. Create an Amazon GuardDuty finding for sensitive data that is transmitted to the SNS topics. Create an AWS Security Hub custom remediation action to block messages that contain sensitive data from being delivered to subscribers of the SNS topics.

    <details>
       <summary>Answer</summary>

      - A: Incorrect -> Amazon Macie is designed for discovering and classifying sensitive data in Amazon S3. While you could use Macie to detect sensitive data in SNS logs stored in S3, it does not natively scan SNS messages in real time.
      - B: Correct -> AWS SNS Inbound Message Data Protection helps detect and protect sensitive data before it is published to the topic. The De-identify operation masks sensitive data in messages before they are stored or transmitted. This approach ensures that sensitive information is handled securely at the point of ingestion, preventing exposure in transaction or debug logs.
      - C: Incorrect -> Encrypting messages using AWS KMS protects data at rest and during transmission, but it does not prevent sensitive data from being published in the first place.
      - D: Icorrect -> Amazon GuardDuty does not inspect SNS messages in real time for sensitive data.

    </details>

63. A security administrator has enabled AWS Security Hub for all the AWS accounts in an organization in AWS Organizations. The security team wants near-real-time response and remediation for deployed AWS resources that do not meet security standards. All changes must be centrally logged for auditing purposes. The organization has reached the quotas for the number of SCPs attached to an OU and SCP document size. The team wants to avoid making any changes to any of the SCPs. The solution must maximize scalability and cost-effectiveness. Which combination of actions should the security administrator take to meet these requirements? (Choose three.)
    - [ ] A. Create an AWS Config custom rule to detect configuration changes to AWS resources. Create an AWS Lambda function to remediate the AWS resources in the delegated administrator AWS account.
    - [ ] B. Use AWS Systems Manager Change Manager to track configuration changes to AWS resources. Create a Systems Manager document to remediate the AWS resources in the delegated administrator AWS account.
    - [ ] C. Create a Security Hub custom action to reference in an Amazon EventBridge event rule in the delegated administrator AWS account.
    - [ ] D. Create an Amazon EventBridge event rule to Invoke an AWS Lambda function that will take action on AWS resources.
    - [ ] E. Create an Amazon EventBridge event rule to invoke an AWS Lambda function that will evaluate AWS resource configuration for a set of API requests and create a finding for noncompllant AWS resources.
    - [ ] F. Create an Amazon EventBridge event rule to invoke an AWS Lambda function on a schedule to assess specific AWS Config rules.

    <details>
       <summary>Answer</summary>

      - A: Incorrect -> While AWS Config is useful, it is more focused on periodic assessments rather than near-real-time detection.
      - B: Incorrect -> This is more for tracking and approval workflows, not real-time enforcement.
      - C: Correct -> Security Hub custom actions allow you to take specific actions when a finding is generated. By referencing it in an EventBridge rule, you can trigger remediation workflows based on Security Hub findings.
      - D: Correct -> EventBridge can be used to detect security violations and trigger an AWS Lambda function to automatically remediate noncompliant AWS resources in near real-time.
      - E: Correct -> This ensures that configuration changes are evaluated in real time and that findings are generated when noncompliance is detected.

    </details>

64. A company runs a global ecommerce website that is hosted on AWS. The company uses Amazon CloudFront to serve content to its user base. The company wants to block inbound traffic from a specific set of countries to comply with recent data regulation policies. Which solution will meet these requirements MOST cost-effectively?
    - [ ] A. Create an AWS WAF web ACL with an IP match condition to deny the countries' IP ranges. Associate the web ACL with the CloudFront distribution.
    - [ ] B. Create an AWS WAF web ACL with a geo match condition to deny the specific countries. Associate the web ACL with the CloudFront distribution.
    - [ ] C. Use the geo restriction feature in CloudFront to deny the specific countries.
    - [ ] D. Use geolocation headers in CloudFront to deny the specific countries.

    <details>
       <summary>Answer</summary>

      - A&B: Incorrect -> AWS WAF incurs extra costs for rules and web ACLs, making it a less cost-effective choice unless additional custom security rules are needed.
      - C: Correct -> CloudFront has a built-in geo restriction feature that allows blocking access to specific countries without additional costs beyond standard CloudFront pricing.
      - D: Incorrect -> Geolocation headers in CloudFront provides location details but does not itself block requests. It requires additional processing at the origin or in AWS WAF, adding complexity and cost.

    </details>

65. A company uses AWS Organizations and has many AWS accounts. The company has a new requirement to use server-side encryption with customer-provided keys (SSE-C) on all new object uploads to Amazon S3 buckets. A security engineer is creating an SCP that includes a Deny effect for the s3:PutObject action. Which condition must the security engineer addz   to the SCP to enforce the new SSE-C requirement?
    - [ ] A. `"condition":{"Null": {"s3:x-amz-server-side-encryption-customer-algorithm": true}}`
    - [ ] B. `"condition":{"StringNotEqual": {"s3:x-amz-server-side-encryption": "aws:kms"}}`
    - [ ] C. `"condition":{"StringNotEqual": {"s3:x-amz-server-side-encryption-customer-algorithm": "AES256"}}`
    - [ ] D. `"condition":{"Null": {"s3:x-amz-server-side-encryption": true}}`

    <details>
       <summary>Answer</summary>

      - A: Correct -> The "Null" condition checks whether the specified key is absent. It should be {"Null": {"s3:x-amz-server-side-encryption-customer-algorithm": "true"}} to deny uploads missing this header. This ensures that SSE-C is always used, because without this header, SSE-C cannot be applied.

    </details>

66. A company has a batch-processing system that uses Amazon S3, Amazon EC2, and AWS Key Management Service (AWS KMS). The system uses two AWS accounts: Account A and Account B. Account A hosts an S3 bucket that stores the objects that will be processed. The S3 bucket also stores the results of the processing. All the S3 bucket objects are encrypted by a KMS key that is managed in Account A. Account B hosts a VPC that has a fleet of EC2 instances that access the S3 bucket in Account A by using statements in the bucket policy. The VPC was created with DNS hostnames enabled and DNS resolution enabled. A security engineer needs to update the design of the system without changing any of the system's code. No AWS API calls from the batch-processing EC2 instances can travel over the internet. Which combination of steps will meet these requirements? (Choose two.)
    - [ ] A. In the Account B VPC, create a gateway VPC endpoint for Amazon S3. For the gateway VPC endpoint, create a resource policy that allows the s3:GetObject, s3:ListBucket, s3:PutObject, and s3:PutObjectAcl actions for the S3 bucket.
    - [ ] B. In the Account B VPC, create an interface VPC endpoint for Amazon S3. For the interface VPC endpoint, create a resource policy that allows the s3:GetObject, s3:ListBucket, s3:PutObject, and s3:PutObjectAcl actions for the S3 bucket.
    - [ ] C. In the Account B VPC, create an interface VPC endpoint for AWS KMS. For the interface VPC endpoint, create a resource policy that allows the kms:Encrypt, kms:Decrypt, and kms:GenerateDataKey actions for the KMS key. Ensure that private DNS is turned on for the endpoint.
    - [ ] D. In the Account B VPC, create an interface VPC endpoint for AWS KMS. For the interface VPC endpoint, create a resource policy that allows the kms:Encrypt, kms:Decrypt, and kms:GenerateDataKey actions for the KMS key. Ensure that private DNS is turned off for the endpoint.
    - [ ] E. In the Account B VPC, verify that the S3 bucket policy allows the s3:PutObjectAcl action for cross-account use. In the Account B VPC, create a gateway VPC endpoint for Amazon S3. For the gateway VPC endpoint, create a resource policy that allows the s3:GetObject, s3:ListBucket, and s3:PutObject actions for the S3 bucket.

    <details>
       <summary>Answer</summary>

      - A: Correct -> Gateway VPC endpoints for S3 allow EC2 instances in a VPC to access Amazon S3 without using the public internet.
      - C: Private DNS must be turned on for the endpoint to allow the EC2 instances to resolve the AWS KMS endpoint using the default KMS domain name (kms.<region>.amazonaws.com).

    </details>

67. A security engineer is designing an IAM policy for a script that will use the AWS CLI. The script currently assumes an IAM role that is attached to three AWS managed IAM policies: AmazonEC2FullAccess, AmazonDynamoDBFullAccess, and AmazonVPCFullAccess. The security engineer needs to construct a least privilege IAM policy that will replace the AWS managed IAM policies that are attached to this role. Which solution will meet these requirements in the MOST operationally efficient way?
    - [ ] A. In AWS CloudTrail, create a trail for management events. Run the script with the existing AWS managed IAM policies. Use IAM Access Analyzer to generate a new IAM policy that is based on access activity in the trail. Replace the existing AWS managed IAM policies with the generated IAM policy for the role.
    - [ ] B. Remove the existing AWS managed IAM policies from the role. Attach the IAM Access Analyzer Role Policy Generator to the role. Run the script. Return to IAM Access Analyzer and generate a least privilege IAM policy. Attach the new IAM policy to the role.
    - [ ] C. Create an account analyzer in IAM Access Analyzer. Create an archive rule that has a filter that checks whether the PrincipalArn value matches the ARN of the role. Run the script. Remove the existing AWS managed IAM policies from the role.
    - [ ] D. In AWS CloudTrail, create a trail for management events. Remove the existing AWS managed IAM policies from the role. Run the script. Find the authorization failure in the trail event that is associated with the script. Create a new IAM policy that includes the action and resource that caused the authorization failure. Repeat the process until the script succeeds. Attach the new IAM policy to the role.

    <details>
       <summary>Answer</summary>

      - A: Correct ->
        - Ensures Operational Efficiency: This approach allows the script to run normally without disruption while CloudTrail logs all the API calls made by the script. IAM Access Analyzer then generates a least privilege IAM policy based on the actual access patterns.
        - Minimizes Manual Work: Instead of manually identifying required permissions (as in option D), this method automates policy generation using IAM Access Analyzer.
        - Ensures Least Privilege: By analyzing the access logs, IAM Access Analyzer can construct a fine-grained policy that only includes necessary permissions.
      - B: Incorrect -> This option suggests removing permissions before running the script, which will cause immediate failures and disrupt operations. Also, there is no feature called "IAM Access Analyzer Role Policy Generator."
      - C: Incorrect -> Creating an account analyzer and an archive rule will not generate a least privilege policy. IAM Access Analyzer does not create IAM policies this way.
      - D: Incorrect -> This method involves an iterative manual process of removing permissions, running the script, checking failures, and adding permissions back—this is inefficient and time-consuming.

    </details>

68. A security engineer is designing a cloud architecture to support an application. The application runs on Amazon EC2 instances and processes sensitive information, including credit card numbers. The application will send the credit card numbers to a component that is running in an isolated environment. The component will encrypt, store, and decrypt the numbers. The component then will issue tokens to replace the numbers in other parts of the application. The component of the application that manages the tokenization process will be deployed on a separate set of EC2 instances. Other components of the application must not be able to store or access the credit card numbers. Which solution will meet these requirements?
    - [ ] A. Use EC2 Dedicated Instances for the tokenization component of the application.
    - [ ] B. Place the EC2 instances that manage the tokenization process into a partition placement group.
    - [ ] C. Create a separate VPDeploy new EC2 instances into the separate VPC to support the data tokenization.
    - [ ] D. Deploy the tokenization code onto AWS Nitro Enclaves that are hosted on EC2 instances.

    <details>
       <summary>Answer</summary>

      - D: Correct -> AWS Nitro Enclaves provides an isolated execution environment for processing highly sensitive data, such as credit card numbers. It is designed for workloads that require secure data processing and tokenization while ensuring that even the parent EC2 instance cannot access the sensitive information.

    </details>

69. A company wants to receive automated email notifications when AWS access keys from developer AWS accounts are detected on code repository sites. Which solution will provide the required email notifications?
    - [ ] A. Create an Amazon EventBridge rule to send Amazon Simple Notification Service (Amazon SNS) email notifications for Amazon GuardDuty `UnauthorizedAccess:IAMUser/lnstanceCredentialExfiltration.OutsideAWS` findings.
    - [ ] B. Change the AWS account contact information for the Operations type to a separate email address. Periodically poll this email address for notifications.
    - [ ] C. Create an Amazon EventBridge rule that reacts to AWS Health events that have a value of Risk for the service category. Configure email notifications by using Amazon Simple Notification Service (Amazon SNS).
    - [ ] D. Implement new anomaly detection software. Ingest AWS CloudTrail logs. Configure monitoring for ConsoleLogin events in the AWS Management Console. Configure email notifications from the anomaly detection software.

    <details>
       <summary>Answer</summary>

      - A: Correct -> Amazon GuardDuty is a threat detection service that monitors for unauthorized behavior in AWS accounts. It has a specific finding type (UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS) that detects when AWS credentials are exposed and used outside AWS.
      - B: Incorrect -> Changing the AWS account contact information does not provide automatic notifications specific to credential exposure.
      - C: Incorrect -> AWS Health events mostly report service issues and do not specifically detect leaked credentials in external repositories.
      - D: Incorrect -> CloudTrail logs ConsoleLogin events, but this does not directly detect AWS credential leaks in code repositories.

    </details>

70. A company deployed an Amazon EC2 instance to a VPC on AWS. A recent alert indicates that the EC2 instance is receiving a suspicious number of requests over an open TCP port from an external source. The TCP port remains open for long periods of time. The company's security team needs to stop all activity to this port from the external source to ensure that the EC2 instance is not being compromised. The application must remain available to other users. Which solution will meet these requirements?
    - [ ] A. Update the network ACL that is attached to the subnet that is associated with the EC2 instance. Add a Deny statement for the port and the source IP addresses.
    - [ ] B. Update the elastic network interface security group that is attached to the EC2 instance to remove the port from the inbound rule list.
    - [ ] C. Update the elastic network interface security group that is attached to the EC2 instance by adding a Deny entry in the inbound list for the port and the source IP addresses.
    - [ ] D. Create a new network ACL for the subnet. Deny all traffic from the EC2 instance to prevent data from being removed.

    <details>
       <summary>Answer</summary>

      - A: Correct -> Network ACLs (NACLs), on the other hand, are stateless and allow both Allow and Deny rules. By adding a Deny rule for the specific port and source IP addresses, the company can effectively block traffic from the external attacker while keeping the application accessible to other legitimate users.
      - BC: Incorrect -> Security Groups (used in options B and C) do not support explicit "Deny" rules—they are stateful and only allow rules that permit traffic, but there is no way to explicitly deny specific sources while allowing others.
      - D: Incorrect -> Creating a new network ACL and denying all traffic from the EC2 instance is too broad and unnecessary—it would completely block the instance’s communication, which is not required.

    </details>

71. A company has AWS accounts that are in an organization in AWS Organizations. A security engineer needs to set up AWS Security Hub in a dedicated account for security monitoring. The security engineer must ensure that Security Hub automatically manages all existing accounts and all new accounts that are added to the organization. Security Hub also must receive findings from all AWS Regions. Which combination of actions will meet these requirements with the LEAST operational overhead? (Choose two.)
    - [ ] A. Configure a finding aggregation Region for Security Hub. Link the other Regions to the aggregation Region.
    - [ ] B. Create an AWS Lambda function that routes events from other Regions to the dedicated Security Hub account. Create an Amazon EventBridge rule to invoke the Lambda function.
    - [ ] C. Turn on the option to automatically enable accounts for Security Hub.
    - [ ] D. Create an SCP that denies the securityhub:DisableSecurityHub permission. Attach the SCP to the organization’s root account.
    - [ ] E. Configure services in other Regions to write events to an AWS CloudTrail organization trail. Configure Security Hub to read events from the trail.

    <details>
       <summary>Answer</summary>

      - A: Correct -> Security Hub supports cross-Region aggregation, allowing you to collect findings from multiple Regions into a single Region. This ensures that Security Hub receives findings from all AWS Regions with minimal manual effort. This approach provides centralized visibility into security findings, reducing operational overhead.
      - B: Incorrect -> This is unnecessary because Security Hub natively supports cross-Region aggregation. Using Lambda adds unnecessary complexity.
      - C: Correct -> Security Hub provides an option to automatically enable Security Hub for new AWS accounts that are added to the organization. This ensures that Security Hub is consistently activated for all existing and future accounts in the AWS Organization without requiring manual intervention. This is the best way to meet the requirement of managing all existing and new accounts automatically.
      - D: Incorrect -> While this could prevent users from disabling Security Hub, it does not help in enabling or managing Security Hub across accounts, which is the main requirement.
      - E: Incorrect -> Security Hub does not rely on CloudTrail to receive findings. Security Hub integrates directly with AWS services to collect findings.

    </details>

72. A security engineer is implementing a solution to allow users to seamlessly encrypt Amazon S3 objects without having to touch the keys directly. The solution must be highly scalable without requiring continual management. Additionally, the organization must be able to immediately delete the encryption keys. Which solution meets these requirements?
    - [ ] A. Use AWS KMS with AWS managed keys and the ScheduleKeyDeletion API with a PendingWindowInDays set to 0 to remove the keys if necessary.
    - [ ] B. Use KMS with AWS imported key material and then use the DeleteImportedKeyMaterial API to remove the key material if necessary.
    - [ ] C. Use AWS CloudHSM to store the keys and then use the CloudHSM API or the PKCS11 library to delete the keys if necessary.
    - [ ] D. Use the Systems Manager Parameter Store to store the keys and then use the service API operations to delete the keys if necessary.

    <details>
       <summary>Answer</summary>

      - A: Incorrect -> AWS does not allow immediate key deletion for AWS-managed keys. The ScheduleKeyDeletion API requires a minimum waiting period of 7 days, which does not meet the "immediate deletion" requirement.
      - B: Correct -> AWS Key Management Service (KMS) allows users to encrypt Amazon S3 objects seamlessly while managing encryption keys behind the scenes. When using AWS KMS with customer-imported key material, you can use the DeleteImportedKeyMaterial API to immediately delete the key material.
      - C: Incorrect -> CloudHSM is a dedicated hardware security module that requires more management overhead.
      - D: Incorrect -> Parameter Store is not meant for cryptographic key management.

    </details>

73. A company needs to implement DNS Security Extensions (DNSSEC) for a specific subdomain. The subdomain is already registered with Amazon Route 53. A security engineer has enabled DNSSEC signing and has created a key-signing key (KSK). When the security engineer tries to test the configuration, the security engineer receives an error for a broken trust chain. What should the security engineer do to resolve this error?
    - [ ] A. Replace the KSK with a zone-signing key (ZSK).
    - [ ] B. Deactivate and then activate the KSK.
    - [ ] C. Create a Delegation Signer (DS) record in the parent hosted zone.
    - [ ] D. Create a Delegation Signer (DS) record in the subdomain.

    <details>
       <summary>Answer</summary>

      - C: Correct -> The error indicating a "broken trust chain" suggests that the parent zone does not have a proper delegation to the subdomain's DNSSEC configuration. For DNSSEC to work correctly, the trust chain must be established from the root domain to the subdomain. This is done by:
        - Signing the subdomain: The security engineer has already enabled DNSSEC signing and created a key-signing key (KSK).
        - Creating a DS record in the parent hosted zone: The Delegation Signer (DS) record contains the hash of the KSK, which allows resolvers to verify the authenticity of the subdomain's DNSSEC signature. This record must be placed in the parent hosted zone.

    </details>

74. A company used AWS Organizations to set up an environment with multiple AWS accounts. The company's organization currently has two AWS accounts, and the company expects to add more than 50 AWS accounts during the next 12 months. The company will require all existing and future AWS accounts to use Amazon GuardDuty. Each existing AWS account has GuardDuty active. The company reviews GuardDuty findings by logging into each AWS account individually. The company wants a centralized view of the GuardDuty findings for the existing AWS accounts and any future AWS accounts. The company also must ensure that any new AWS account has GuardDuty automatically turned on. Which solution will meet these requirements?
    - [ ] A. Enable AWS Security Hub in the organization's management account. Configure GuardDuty within the management account to send all GuardDuty findings to Security Hub.
    - [ ] B. Create a new AWS account in the organization. Enable GuardDuty in the new account. Designate the new account as the delegated administrator account for GuardDuty. Configure GuardDuty to add existing accounts as member accounts. Select the option to automatically add new AWS accounts to the organization.
    - [ ] C. Create a new AWS account in the organization. Enable GuardDuty in the new account. Enable AWS Security Hub in each account. Select the option to automatically add new AWS accounts to the organization.
    - [ ] D. Enable AWS Security Hub in the organization's management account. Designate the management account as the delegated administrator account for Security Hub. Add existing accounts as member accounts. Select the option to automatically add new AWS accounts to the organization. Send all Security Hub findings to the organization's GuardDuty account.

    <details>
       <summary>Answer</summary>

      - A: Incorrect -> Security Hub aggregates security findings from multiple AWS security services, but simply enabling it in the management account does not make it a centralized GuardDuty view.
      - B: Correct -> AWS allows the designation of a delegated administrator account for GuardDuty. This account can centrally manage GuardDuty findings across all AWS accounts in the organization. By enabling GuardDuty in this new account and making it the delegated administrator, all GuardDuty findings from the existing and future accounts can be viewed centrally. GuardDuty provides an option to automatically add new AWS accounts as member accounts. This ensures that any new AWS account in the organization will have GuardDuty enabled without manual intervention.
      - C: Incorrect -> This option does not specify setting up a delegated administrator for GuardDuty, meaning it does not fully centralize the findings.
      - D: Incorrect -> Security Hub does not serve as the centralized GuardDuty findings manager. Instead, GuardDuty should be managed through a delegated administrator.

    </details>

75. A company is storing data in Amazon S3 Glacier. The security engineer implemented a new vault lock policy for 10TB of data and called initiate-vault-lock operation 12 hours ago. The audit team identified a typo in the policy that is allowing unintended access to the vault. What is the MOST cost-effective way to correct this?
    - [ ] A. Call the abort-vault-lock operation. Update the policy. Call the initiate-vault-lock operation again.
    - [ ] B. Copy the vault data to a new S3 bucket. Delete the vault. Create a new vault with the data.
    - [ ] C. Update the policy to keep the vault lock in place.
    - [ ] D. Update the policy. Call initiate-vault-lock operation again to apply the new policy.

    <details>
       <summary>Answer</summary>

      - A: Correct -> Amazon S3 Glacier Vault Lock allows you to enforce compliance controls on a vault with a lockable policy. When the initiate-vault-lock operation is called, the vault enters a lock-in-progress state. During this phase (which can last up to 24 hours), you can abort the lock operation if needed. Since the vault lock has only been in place for 12 hours, it is still in the lock-in-progress state, so you can use the abort-vault-lock operation to cancel it. After aborting, you can update the policy and initiate the vault lock process again.

    </details>

76. A company uses HTTP Live Streaming (HLS) to stream live video content to paying subscribers by using Amazon CloudFront. HLS splits the video content into chunks so that the user can request the right chunk based on different conditions. Because the video events last for several hours, the total video is made up of thousands of chunks. The origin URL is not disclosed, and every user is forced to access the CloudFront URL. The company has a web application that authenticates the paying users against an internal repository and a CloudFront key pair that is already issued. What is the simplest and MOST effective way to protect the content?
    - [ ] A. Develop the application to use the CloudFront key pair to create signed URLs that users will use to access the content.
    - [ ] B. Develop the application to use the CloudFront key pair to set the signed cookies that users will use to access the content.
    - [ ] C. Develop the application to issue a security token that Lambda@Edge will receive to authenticate and authorize access to the content.
    - [ ] D. Keep the CloudFront URL encrypted inside the application, and use AWS KMS to resolve the URL on-the-fly after the user is authenticated.

    <details>
       <summary>Answer</summary>

      - A: Incorrect -> Since HLS splits video content into many small chunks (thousands in this case), signed URLs (Option A) would require generating and managing thousands of signed URLs for each user session. This would be inefficient.
      - B: Correct ->  With signed cookies, the application authenticates users and issues a signed cookie. The user's browser includes this cookie in every request to CloudFront, granting seamless access to all chunks without requiring individual signed URLs.
      - C: Incorrect -> Unlike Option C (Lambda@Edge), which introduces extra complexity and potential latency by requiring Lambda function execution for each request, signed cookies allow CloudFront to efficiently validate requests without additional processing.
      - D: Incorrect -> Keeping URLs encrypted inside the application and decrypting them using AWS KMS adds unnecessary complexity. This approach does not provide better security than signed cookies and can create performance bottlenecks.

    </details>

77. AWS CloudTrail is being used to monitor API calls in an organization. An audit revealed that CloudTrail is failing to deliver events to Amazon S3 as expected. What initial actions should be taken to allow delivery of CloudTrail events to S3? (Choose two.)
    - [ ] A. Verify that the S3 bucket policy allow CloudTrail to write objects.
    - [ ] B. Verify that the IAM role used by CloudTrail has access to write to Amazon CloudWatch Logs.
    - [ ] C. Remove any lifecycle policies on the S3 bucket that are archiving objects to Amazon Glacier.
    - [ ] D. Verify that the S3 bucket defined in CloudTrail exists.
    - [ ] E. Verify that the log file prefix defined in CloudTrail exists in the S3 bucket.

    <details>
       <summary>Answer</summary>

      - A: Correct -> CloudTrail must have the necessary permissions to write log files to the specified S3 bucket. The bucket policy should explicitly allow CloudTrail's service principal (cloudtrail.amazonaws.com) to write objects.
      - D: Correct -> If the specified S3 bucket does not exist or has been deleted, CloudTrail will fail to deliver logs. Ensuring that the bucket exists is a fundamental step in troubleshooting.

    </details>

78. What is the MOST operationally efficient way to meet this requirement?
    - [ ] A. Create an AWS Lambda function to list all certificates and to go through each certificate to describe the certificate by using the AWS SDK. Filter on the NotAfter attribute and send an email notification. Use an Amazon EventBridge rate expression to schedule the Lambda function to run daily.
    - [ ] B. Create an Amazon CloudWatch alarm. Add all the certificate ARNs in the AWS/CertificateManager namespace to the DaysToExpiry metric. Configure the alarm to publish a notification to an Amazon Simple Notification Service (Amazon SNS) topic when the value for the DaysToExpiry metric is less than or equal to 31.
    - [ ] C. Set up AWS Security Hub. Turn on the AWS Foundational Security Best Practices standard with integrated ACM to send findings. Configure and use a custom action by creating a rule to match the pattern from the ACM findings on the NotBefore attribute as the event source. Create an Amazon Simple Notification Service (Amazon SNS) topic as the target.
    - [ ] D. Create an Amazon EventBridge rule by using a predefined pattern for ACM Choose the metric in the ACM Certificate Approaching Expiration event as the event pattern. Create an Amazon Simple Notification Service (Amazon SNS) topic as the target.

    <details>
       <summary>Answer</summary>

      D.

    </details>

79. A Security Analyst attempted to troubleshoot the monitoring of suspicious security group changes. The Analyst was told that there is an Amazon CloudWatch alarm in place for these AWS CloudTrail log events. The Analyst tested the monitoring setup by making a configuration change to the security group but did not receive any alerts. Which of the following troubleshooting steps should the Analyst perform?
    - [ ] A. Ensure that CloudTrail and S3 bucket access logging is enabled for the Analyst's AWS account. B. Verify that a metric filter was created and then mapped to an alarm. Check the alarm notification action.
    - [ ] B. Verify that a metric filter was created and then mapped to an alarm. Check the alarm notification action.
    - [ ] C. Check the CloudWatch dashboards to ensure that there is a metric configured with an appropriate dimension for security group changes.
    - [ ] D. Verify that the Analyst's account is mapped to an IAM policy that includes permissions for cloudwatch: GetMetricStatistics and Cloudwatch: ListMetrics.

    <details>
       <summary>Answer</summary>

      B: Correct -> AWS CloudTrail records API activity, including security group changes, but CloudTrail alone does not generate alerts. To trigger an alarm for security group changes, a CloudWatch Logs metric filter must be created based on the specific log events from CloudTrail. The metric filter should be mapped to a CloudWatch alarm that is configured to trigger when a security group modification event occurs. Even if the alarm is correctly configured, the alert may not be received if the SNS topic (or another notification action) is misconfigured or the recipient is not subscribed.

    </details>

80. An Amazon API Gateway API invokes an AWS Lambda function that needs to interact with a software-as-a-service (SaaS) platform. A unique client token is generated in the SaaS platform to grant access to the Lambda function. A security engineer needs to design a solution to encrypt the access token at rest and pass the token to the Lambda function at runtime. Which solution will meet these requirements MOST cost-effectively?
    - [ ] A. Store the client token as a secret in AWS Secrets Manager. Use the AWS SDK to retrieve the secretin the Lambda function.
    - [ ] B. Configure a token-based Lambda authorizer in API Gateway.
    - [ ] C. Store the client token as a SecureString parameter in AWS Systems Manager Parameter Store. Use the AWS SDK to retrieve the value of the SecureString parameter in the Lambda function.
    - [ ] D. Use AWS Key Management Service (AWS KMS) to encrypt the client token. Pass the token to the Lambda function at runtime through an environment variable.

    <details>
       <summary>Answer</summary>

      - A: Incorrect -> While AWS Secrets Manager also encrypts secrets and allows retrieval, it is more expensive than AWS Systems Manager Parameter Store, making it less cost-effective.
      - B: Incorrect -> This approach is not relevant to securely storing the token at rest; it is used for authentication and authorization of API Gateway requests.
      - C: Correct.
      - D: Incorrect -> Encrypting the token manually with AWS KMS and passing it through an environment variable is less secure, as environment variables persist in memory and can be exposed in logs.

    </details>

81. A company is using an Amazon CloudFront distribution to deliver content from two origins. One origin is a dynamic application that is hosted on Amazon EC2 instances. The other origin is an Amazon S3 bucket for static assets. A security analysis shows that HTTPS responses from the application do not comply with a security requirement to provide an X-Frame-Options HTTP header to prevent frame-related cross-site scripting attacks. A security engineer must make the full stack compliant by adding the missing HTTP header to the responses. Which solution will meet these requirements?
    - [ ] A. Create a Lambda@Edge function. Include code to add the X-Frame-Options header to the response. Configure the function to run in response to the CloudFront origin response event.
    - [ ] B. Create a Lambda@Edge function. Include code to add the X-Frame-Options header to the response. Configure the function to run in response to the CloudFront viewer request event.
    - [ ] C. Update the CloudFront distribution by adding X-Frame-Options to custom headers in the origin settings.
    - [ ] D. Customize the EC2 hosted application to add the X-Frame-Options header to the responses that are returned to CloudFront.

    <details>
       <summary>Answer</summary>

      - A: Correct ->
        - A Lambda@Edge function allows modifying HTTP responses before they reach the client.
        - By setting it to run on the CloudFront origin response event, it ensures that all responses from both the EC2-based dynamic application and the S3 bucket include the X-Frame-Options header.
        - This method does not require modifying the origin application or the S3 configuration.
        - It centralizes security enforcement at the CloudFront layer, ensuring uniform compliance.
      - B: Incorrect -> ThThe viewer request event runs before CloudFront forwards the request to the origin.
      - C: Incorrect -> CloudFront's origin settings only allow adding custom headers in the request to the origin (not in the response).
      - D: Incorrect -> While updating the EC2-hosted application would work for dynamic content, it does not apply to responses from the S3 bucket.

    </details>

82. A security engineer is investigating a malware infection that has spread across a set of Amazon EC2 instances. A key indicator of the compromise is outbound traffic on TCP port 2905 to a set of command and control hosts on the internet. The security engineer creates a network ACL rule that denies the identified outbound traffic. The security engineer applies the network ACL rule to the subnet of the EC2 instances. The security engineer must identify any EC2 instances that are trying to communicate on TCP port 2905. Which solution will identify the affected EC2 instances with the LEAST operational effort?
    - [ ] A. Create a Network Access Scope in Amazon VPC Network Access Analyzer. Use the Network Access Scope to identify EC2 instances that try to send traffic to TCP port 2905.
    - [ ] B. Enable VPC flow logs for the VPC where the affected EC2 instances are located. Configure the flow logs to capture rejected traffic. In the flow logs, search for REJECT records that have a destination TCP port of 2905.
    - [ ] C. Enable Amazon GuardDuty. Create a custom GuardDuty IP list to create a finding when an EC2 instance tries to communicate with one of the command and control hosts. Use Amazon Detective to identify the EC2 instances that initiate the communication.
    - [ ] D. Create a firewall in AWS Network Firewall. Attach the firewall to the subnet of the EC2 instances. Create a custom rule to identify and log traffic from the firewall on TCP port 2905. Create an Amazon CloudWatch Logs metric filter to identify firewall logs that reference traffic on TCP port 2905.

    <details>
       <summary>Answer</summary>

      - A: Incorrect -> Network Access Analyzer helps analyze network access policies and paths but does not provide real-time monitoring or logs of actual traffic attempts. It identifies potential access issues rather than actively logging traffic from infected instances.
      - B: Correct -> VPC Flow Logs provide a straightforward way to capture network traffic metadata for all instances in a VPC without requiring additional infrastructure. By filtering flow logs for REJECT records with destination TCP port 2905, the security engineer can quickly identify which EC2 instances are attempting to communicate with the command and control (C2) hosts.
      - C: Incorrect -> GuardDuty can detect malicious activity, but it does not natively analyze network ACL blocks. Setting up custom threat lists and correlating findings in Detective adds operational complexity.
      - D: Incorrect -> Setting up an AWS Network Firewall is more complex and requires additional infrastructure. CloudWatch Logs metric filters would need continuous monitoring and custom rule creation, increasing operational effort.

    </details>

83. A company runs workloads on Amazon EC2 instances. The company needs to continually monitor the EC2 instances for software vulnerabilities and must display the findings in AWS Security Hub. The company must not install agents on the EC2 instances. Which solution will meet these requirements?
    - [ ] A. Enable Amazon Inspector. Set the scan mode to hybrid scanning. Enable the integration for Amazon Inspector in Security Hub.
    - [ ] B. Use Security Hub to enable the AWS Foundational Security Best Practices standard. Wait for Security Hub to generate the findings.
    - [ ] C. Enable Amazon GuardDuty. Initiate on-demand malware scans by using GuardDuty Malware Protection. Enable the integration for GuardDuty in Security Hub.
    - [ ] D. Use AWS Config managed rules to detect EC2 software vulnerabilities. Ensure that Security Hub has the AWS Config integration enabled.

    <details>
       <summary>Answer</summary>

      - A: Amazon Inspector is an AWS service designed specifically for identifying software vulnerabilities and unintended network exposure of Amazon EC2 instances and container images in Amazon Elastic Container Registry (ECR). It provides continuous scanning for Common Vulnerabilities and Exposures (CVEs) without requiring an agent when using hybrid scanning. Hybrid scanning mode enables agentless vulnerability detection, which meets the requirement of not installing agents. Amazon Inspector integrates with AWS Security Hub, allowing vulnerability findings to be displayed in Security Hub.

    </details>

84. A security engineer needs to analyze Apache web server access logs that are stored in an Amazon S3 bucket. Amazon EC2 instance web servers generated the logs. The EC2 instances have the Amazon CloudWatch agent installed and configured to report their access logs.  The security engineer needs to use a query in Amazon Athena to analyze the logs. The query must identify IP addresses that have attempted and failed to access restricted web server content held at the /admin URL path. The query also must identify the URLs that the IP addresses attempted to access. Which query will meet these requirements?
    - [ ] A. SELECT client_ip, client_request FROM logs WHERE client_request LIKE '%/admin%' AND server_status = '403'
    - [ ] B. SELECT client_ip FROM logs WHERE client_request CONTAINS '%/admin%' AND server_status = '401' GROUP BY client_ip
    - [ ] C. SELECT DISTINCT (client_ip), client_request, client_id FROM logs WHERE server status = '403' LIMIT 1000
    - [ ] D. SELECT DISTINCT (client_ip), client_request FROM logs WHERE user_id <> 'admin' AND server_status = '401!'

    <details>
       <summary>Answer</summary>

      - A: Correct
      - B: Incorrect -> Only retrieves client_ip, but does not return the URLs attempted, which is required.
      - C: Incorrect -> Does not specifically filter attempts to /admin, which is a requirement.
      - D: Incorrect -> Assumes filtering by user_id <> 'admin' is necessary, which is not required.

    </details>

85. A company uses Amazon Cognito as an OAuth 2.0 identity platform for its web and mobile applications. The company needs to capture successful and unsuccessful login attempts. The company also needs to query the data about the login attempts. Which solution will meet these requirements?
    - [ ] A. Configure Cognito to send logs of user activity to Amazon CloudWatch. Configure Amazon EventBridge to invoke an AWS Lambda function to export the logs to an Amazon S3 bucket. Use Amazon Athena to query the logs for event names of SignUp with event sources of cognito-idp.amazonaws.com.
    - [ ] B. Enable AWS CloudTrail to deliver logs to an Amazon S3 bucket. Use Amazon Athena to query the logs for event names of InitiateAuth with event sources of cognito-idp.amazonaws.com.
    - [ ] C. Configure AWS CloudTrail to send Cognito CloudTrail events to Amazon CloudWatch for monitoring. Query the event logs for event names of SignUp with event sources of cognito-idp.amazonaws.com.
    - [ ] D. Configure Amazon CloudWatch metrics to monitor and report Cognito events. Create a CloudWatch dashboard for the provided metrics. Display the Cognito user pools for event names of InitiateAuth with event sources of cognito-idp.amazonaws.com.

    <details>
       <summary>Answer</summary>

      - B.

    </details>

86. A company is migrating its Amazon EC2 based applications to use Instance Metadata Service Version 2 (IMDSv2). A security engineer needs to determine whether any of the EC2 instances are still using Instance Metadata Service Version 1 (IMDSv1). What should the security engineer do to confirm that the IMDSv1 endpoint is no longer being used?
    - [ ] A. Configure logging on the Amazon CloudWatch agent for IMDSv1 as part of EC2 instance startup. Create a metric filter and a CloudWatch dashboard. Track the metric in the dashboard.
    - [ ] B. Create an Amazon CloudWatch dashboard. Verify that the EC2:MetadataNoToken metric is zero across all EC2 instances. Monitor the dashboard.
    - [ ] C. Create a security group that blocks access to HTTP for the IMDSv1 endpoint. Attach the security group to all EC2 instances.
    - [ ] D. Configure user data scripts for all EC2 instances to send logging information to AWS CloudTrail when IMDSv1 is used. Create a metric filter and an Amazon CloudWatch dashboard. Track the metric in the dashboard.

    <details>
       <summary>Answer</summary>

      - B: Correct -> IMDSv2 requires requests to the Instance Metadata Service to include a session token. IMDSv1 does not require a session token and is considered less secure. AWS provides the EC2:MetadataNoToken metric in Amazon CloudWatch, which tracks the number of IMDSv1 requests (i.e., requests without a token). If EC2:MetadataNoToken is greater than zero, some EC2 instances are still using IMDSv1. By monitoring this metric in a CloudWatch dashboard, the security engineer can confirm whether any EC2 instances are still using IMDSv1.

    </details>

87. A company uses AWS Config rules to identify Amazon S3 buckets that are not compliant with the company’s data protection policy. The S3 buckets are hosted in several AWS Regions and several AWS accounts. The accounts are in an organization in AWS Organizations. The company needs a solution to remediate the organization’s existing noncompliant S3 buckets and any noncompliant S3 buckets that are created in the future. Which solution will meet these requirements?
    - [ ] A. Deploy an AWS Config aggregator with organization-wide resource data aggregation. Create an AWS Lambda function that responds to AWS Config findings of noncompliant S3 buckets by deleting or reconfiguring the S3 buckets.
    - [ ] B. Deploy an AWS Config aggregator with organization-wide resource data aggregation. Create an SCP that contains a Deny statement that prevents the creation of new noncompliant S3 buckets. Apply the SCP to all OUs in the organization.
    - [ ] C. Deploy an AWS Config aggregator that scopes only the accounts and Regions that the company currently uses. Create an AWS Lambda function that responds to AWS Config findings of noncompliant S3 buckets by deleting or reconfiguring the S3 buckets.
    - [ ] D. Deploy an AWS Config aggregator that scopes only the accounts and Regions that the company currently uses. Create an SCP that contains a Deny statement that prevents the creation of new noncompliant S3 buckets. Apply the SCP to all OUs in the organization.

    <details>
       <summary>Answer</summary>

      - A.

    </details>

88. A company wants to start processing sensitive data on Amazon EC2 instances. The company will use Amazon CloudWatch Logs to monitor, store, and access log files from the EC2 instances. The company’s developers use CloudWatch Logs for troubleshooting. A security engineer must implement a solution that prevents the developers from viewing the sensitive data. The solution must automatically apply to any new log groups that are created in the account in the future. Which solution will meet these requirements?
    - [ ] A. Create a CloudWatch Logs account-wide data protection policy. Specify the appropriate data identifiers for the policy. Ensure that the developers do not have the logs:Unmask IAM permission.
    - [ ] B. Export the CloudWatch Logs data to an Amazon S3 bucket. Set up automated discovery by using Amazon Macie on the S3 bucket. Create a custom data identifier for the sensitive data. Remove the developers’ access to CloudWatch Logs. Grant permissions for the developers to view the exported log data in Amazon S3.
    - [ ] C. Export the CloudWatch Logs data to an Amazon S3 bucket. Set up automated discovery by using Amazon Macie on the S3 bucket. Specify the appropriate managed data identifiers. Remove the developers’ access to CloudWatch Logs. Grant permissions for the developers to view the exported log data in Amazon S3.
    - [ ] D. Create a CloudWatch Logs data protection policy for each log group. Specify the appropriate data identifiers for the policy. Ensure that the developers do not have the logs:Unmask IAM permission.

    <details>
       <summary>Answer</summary>

      - A: Correnct -> AWS provides CloudWatch Logs data protection policies, which allow you to automatically detect and mask sensitive data in logs. An account-wide policy ensures that all existing and future log groups automatically adhere to the same security measures. You can specify AWS-managed data identifiers (such as PII, financial data, and credentials) to automatically detect sensitive data. By default, masked data remains hidden unless a user has the logs:Unmask permission. Ensuring that developers do not have this permission prevents them from viewing sensitive data.

    </details>

89. A company uses an organization in AWS Organizations to help separate its Amazon EC2 instances and VPCs. The company has separate OUs for development workloads and production workloads. A security engineer must ensure that only AWS accounts in the production OU can write VPC flow logs to an Amazon S3 bucket. The security engineer is configuring the S3 bucket policy with a Condition element to allow the s3:PutObject action for VPC flow logs. How should the security engineer configure the Condition element to meet these requirements?
    - [ ] A. Set the value of the aws:SourceOrgID condition key to be the organization ID.
    - [ ] B. Set the value of the aws:SourceOrgPaths condition key to be the Organizations entity path of the production OU.
    - [ ] C. Set the value of the aws:ResourceOrgID condition key to be the organization ID.
    - [ ] D. Set the value of the aws:ResourceOrgPaths condition key to be the Organizations entity path of the production OU.

    <details>
       <summary>Answer</summary>

      - aws:SourceOrgID – Specifies the organization ID of the AWS Organizations structure. It applies to requests made from within the organization but does not differentiate between different OUs. Since we need to restrict access specifically to the production OU, this is not sufficient.
      - aws:SourceOrgPaths – Specifies the Organizations entity path (i.e., the hierarchical path within AWS Organizations) of the account making the request. This is useful when needing to allow only accounts within a specific OU to perform an action.
      - aws:ResourceOrgID – Refers to the AWS Organization ID of the resource being accessed, which applies only to AWS-owned resources such as S3 buckets. However, the source of the request (VPC flow logs from an EC2 instance) is what we need to restrict, so this is not applicable.
      - aws:ResourceOrgPaths – Similar to aws:SourceOrgPaths, but this applies to the resource being accessed, not the requester. Since the S3 bucket is not part of an OU (it belongs to an AWS account), this condition key is not applicable.
      - B is correct.

    </details>

90. A company uses AWS Organizations to manage a small number of AWS accounts. However, the company plans to add 1,000 more accounts soon. The company allows only a centralized security team to create IAM roles for all AWS accounts and teams. Application teams submit requests for IAM roles to the security team. The security team has a backlog of IAM role requests and cannot review and provision the IAM roles quickly. The security team must create a process that will allow application teams to provision their own IAM roles. The process must also limit the scope of IAM roles and prevent privilege escalation. Which solution will meet these requirements with the LEAST operational overhead?
    - [ ] A. Create an IAM group for each application team. Associate policies with each IAM group. Provision IAM users for each application team member. Add the new IAM users to the appropriate IAM group by using role-based access control (RBAC).
    - [ ] B. Delegate application team leads to provision IAM roles for each team. Conduct a quarterly review of the IAM roles the team leads have provisioned. Ensure that the application team leads have the appropriate training to review IAM roles.
    - [ ] C. Put each AWS account in its own OU. Add an SCP to each OU to grant access to only the AWS services that the teams plan to use. Include conditions in the AWS account of each team.
    - [ ] D. Create an SCP and a permissions boundary for IAM roles. Add the SCP to the root OU so that only roles that have the permissions boundary attached can create any new IAM roles.

    <details>
       <summary>Answer</summary>

      - D: Correct ->  SCPs allow centralized control over IAM permissions across AWS Organizations. By applying an SCP at the root Organizational Unit (OU) level, you ensure that IAM role creation follows security guidelines across all AWS accounts. A permissions boundary limits the maximum permissions an IAM role can have, even if broader permissions are granted elsewhere. This prevents privilege escalation and ensures application teams can only create roles within predefined security constraints. Once the SCP and permissions boundary are set up, the security team does not need to review each IAM role manually. Application teams can provision their own roles within the defined constraints, reducing the backlog.

    </details>

91. A medical company recently completed an acquisition and inherited an existing AWS environment. The company has an upcoming audit and is concerned about the compliance posture of its acquisition. The company must identify personal health information inside Amazon S3 buckets and must identify S3 buckets that are publicly accessible. The company needs to prepare for the audit by collecting evidence in the environment. Which combination of steps will meet these requirements with the LEAST operational overhead? (Choose three.)
    - [ ] A. Enable Amazon Macie. Run an on-demand sensitive data discovery job that uses the PERSONAL_INFORMATION managed data identifier.
    - [ ] B. Use AWS Glue with the Detect PII transform to identify sensitive data and to mask the sensitive data.
    - [ ] C. Enable AWS Audit Manager. Create an assessment by using a supported framework.
    - [ ] D. Enable Amazon GuardDuty S3 Protection. Document any findings that are related to suspicious access of S3 buckets.
    - [ ] E. Enable AWS Security Hub. Use the AWS Foundational Security Best Practices standard. Review the controls dashboard for evidence of failed S3 Block Public Access controls.
    - [ ] F. Enable AWS Config. Set up the s3-bucket-public-write-prohibited AWS Config managed rule.

    <details>
       <summary>Answer</summary>

      - A: Correct -> Amazon Macie is an AWS service designed to automatically detect sensitive data, including personal health information (PHI) inside Amazon S3 buckets. Running an on-demand discovery job with the PERSONAL_INFORMATION managed data identifier helps in quickly identifying any PHI in the acquired S3 buckets.
      - E: Correct -> AWS Security Hub provides a centralized dashboard for security and compliance findings across AWS accounts.
      - F: Correnct -> AWS Config tracks configuration changes in your environment and can enforce compliance rules.

    </details>

92. An AWS account includes two S3 buckets: bucket1 and bucket2. The bucket2 does not have a policy defined, but bucket1 has the following bucket policy. In addition, the same account has an IAM User named `alice`, with the following IAM policy. Which buckets can user `alice` access?

    ```json
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:user/alice"},
                "Action": "S3:*",
                "Resource": ["arn:aws:s3:::bucket1", "arn:aws:s3:::bucket1/*"]
            }
        ]
    }
    ```

    ```json
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "S3:*",
                "Resource": ["arn:aws:s3:::bucket2", "arn:aws:s3:::bucket2/*"]
            }
        ]
    }
    ```

    - [ ] A. Bucket1 only
    - [ ] B. Bucket2 only
    - [ ] C. Both bucket1 and bucket2
    - [ ] D. Neither bucket1 nor bucket2

    <details>
       <summary>Answer</summary>

      - The bucket policy for bucket1 explicitly allows alice full access (S3:*) to both the bucket itself (arn:aws:s3:::bucket1) and all objects within it (arn:aws:s3:::bucket1/*). Since the bucket policy is applied at the bucket level and grants alice permissions explicitly, alice has full access to bucket1.
      - The bucket2 does not have a bucket policy (meaning there are no explicit deny or allow statements at the bucket level). The IAM policy attached to alice grants alice full access (S3:*) to both bucket2 and its objects (arn:aws:s3:::bucket2, arn:aws:s3:::bucket2/*). Since IAM policies apply directly to the user and no bucket policy contradicts this permission, alice has full access to bucket2. alice has full access to both bucket1 and bucket2, as both the bucket policy (for bucket1) and the IAM policy (for bucket2) grant access.

    </details>

93. A security engineer received an Amazon GuardDuty alert indicating a finding involving the Amazon EC2 instance that hosts the company's primary website. The GuardDuty finding received read: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration. The security engineer confirmed that a malicious actor used API access keys intended for the EC2 instance from a country where the company does not operate. The security engineer needs to deny access to the malicious actor. What is the first step the security engineer should take?
    - [ ] A. Open the EC2 console and remove any security groups that allow inbound traffic from 0.0.0.0/0.
    - [ ] B. Install the AWS Systems Manager Agent on the EC2 instance and run an inventory report.
    - [ ] C. Install the Amazon Inspector agent on the host and run an assessment with the CVE rules package.
    - [ ] D. Open the IAM console and revoke all IAM sessions that are associated with the instance profile.

    <details>
       <summary>Answer</summary>

      - D: Correct -> The GuardDuty finding UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration indicates that credentials associated with the IAM role assigned to the EC2 instance were compromised and used from an unauthorized location. To mitigate this issue, the first and most immediate action is to revoke all active IAM sessions associated with the instance profile. This prevents the malicious actor from continuing to use the compromised credentials.

    </details>
