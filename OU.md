# **AWS 组织策略关键字解析**

在 AWS 组织（AWS Organizations）中，以下关键字用于 **服务控制策略（SCP）** 和 **IAM 策略** 来限制资源访问，特别是在跨账户操作时。

---

## **1. `aws:SourceOrgID`（请求来源组织ID）**

- **含义**：表示请求者（用户或服务）所属的 AWS 组织 ID。
- **使用场景**：限制某些 API 调用只能由特定组织的账户执行，防止外部账户访问。

你是一家大公司 A，旗下有多个子公司（AWS 账户）。你希望邮件服务器（AWS 资源）只接受来自本公司员工的邮件，而不接受外部公司的邮件：

```json
"Condition": {
    "StringEquals": {
        "aws:SourceOrgID": "o-1234567890"
    }
}
```

## **2. `aws:SourceOrgPaths`（请求来源组织路径）**

- **含义**：表示请求者所在的组织路径，包含组织结构层级信息。
- **使用场景**：可以细粒度控制，允许组织内的某个 OU（组织单元）访问资源，而不是整个组织。

A 公司 IT 部门的组织架构如下：

```text
o-1234567890（A公司）
 ├── ou-abc123（IT 部门）
 ├── ou-def456（财务部门）
 ├── ou-ghi789（市场部门）
```

你希望只有 IT 部门的账户能访问邮件服务器：

```json
"Condition": {
    "StringLike": {
        "aws:SourceOrgPaths": "o-1234567890/r-xxxx/ou-abc123/*"
    }
}
```

## **3. `aws:ResourceOrgID`（资源所属组织ID）**

- **含义**：表示资源（如 S3 存储桶、EC2 实例等）所属的 AWS 组织 ID。
- **使用场景**：用于确保访问的资源属于指定的组织，防止跨组织访问。

A 公司有一个 S3 存储桶 company-data，你希望只有 A 公司的账户才能访问：

```json
"Condition": {
    "StringEquals": {
        "aws:ResourceOrgID": "o-1234567890"
    }
}
```

## **4. `aws:ResourceOrgPaths`（资源所属组织路径）**

- **含义**：表示资源所属的组织路径，包含资源所在的 OU 信息。
- **使用场景**：用于细粒度控制，确保只能访问特定 OU 内的资源。

A 公司 IT 部门的 S3 存储桶 it-data 和市场部门的 marketing-data：

```text
o-1234567890（A公司）
 ├── ou-abc123（IT 部门）
 │    ├── it-data（S3存储桶）
 ├── ou-ghi789（市场部门）
      ├── marketing-data（S3存储桶）
```

你希望 IT 部门的账户只能访问 it-data：

```json
"Condition": {
    "StringLike": {
        "aws:ResourceOrgPaths": "o-1234567890/r-xxxx/ou-abc123/*"
    }
}
```

## 总结

|关键字|作用对象|作用范围|使用场景|
|-|-|-|-|
|`aws:SourceOrgID`|请求来源|限制API请求必须来自某个AWS组织|限制API只能由自己组织调用|
|`aws:SourceOrgPaths`|请求来源|限制API请求必须来自某个组织路径（OU 内）|限制API只能由特定 OU 访问|
|`aws:ResourceOrgID`|资源|限制资源必须属于某个AWS组织|防止访问外部组织的资源|
|`aws:ResourceOrgPaths`|资源|限制资源必须属于某个组织|限制特定OU的用户访|
