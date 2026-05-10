import * as s3 from 'aws-cdk-lib/aws-s3'
import { Construct } from 'constructs'

export class StorageStack extends Construct {
  constructor(scope: Construct, id: string) {
    super(scope, id)

    const uploadsBucket = new s3.Bucket(this, 'UploadsBucket', {
      versioned: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    })
  }
}
