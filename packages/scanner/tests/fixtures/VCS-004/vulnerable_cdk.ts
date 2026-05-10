import * as s3 from 'aws-cdk-lib/aws-s3'
import { Construct } from 'constructs'

export class StorageStack extends Construct {
  constructor(scope: Construct, id: string) {
    super(scope, id)

    // No blockPublicAccess — publicly readable
    const uploadsBucket = new s3.Bucket(this, 'UploadsBucket', {
      versioned: true,
    })

    // blockPublicAccess present but not BLOCK_ALL
    const assetsBucket = new s3.Bucket(this, 'AssetsBucket', {
      blockPublicAccess: new s3.BlockPublicAccess({
        blockPublicAcls: false,
        blockPublicPolicy: true,
        ignorePublicAcls: true,
        restrictPublicBuckets: true,
      }),
    })
  }
}
