# AWS Permission Mapper

This will allow the ability to map boto3 SDK calls to the IAM permission(s) that is needed. The JSON could then be parsed for use.

## Process

1. Iterate through each AWS service and its SDK calls
2. Attempt each SDK call and capture AccessDenied errors
3. Extract required IAM permission from the error
4. Temporarily add the permission to the IAM role
5. Retry the SDK call:
   - If successful: Record the permission, remove it, move to next call
   - If failed: Add next required permission, retry from step 5
6. Repeat for all SDK calls and services

## Usage

1. Install dependencies:

   ```python
   pip install boto3
   ```

2. Run the script:

   ```python
   python aws_permission_mapper.py
   ```

3. Choose to map a single service or all services
4. Results are saved to a JSON file
