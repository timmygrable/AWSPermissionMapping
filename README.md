# AWS Permission Mapper

This will allow the ability to map boto3 SDK calls to the IAM permission(s) that is needed. The JSON could then be parsed for use.

## Usage

1. Install dependencies:
   ```
   pip install boto3
   ```

2. Run the script:
   ```
   python aws_permission_mapper.py
   ```

3. Choose to map a single service or all services
4. Results are saved to a JSON file
