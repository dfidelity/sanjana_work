WITH cte AS (
  SELECT
    SUBSTRING(
      SUBSTRING(key, 1, POSITION('.' IN key) - 1),
      LENGTH(SUBSTRING(key, 1, POSITION('.' IN key) - 1)) - POSITION('/' IN REVERSE(SUBSTRING(key, 1, POSITION('.' IN key) - 1))) + 2
    ) AS athena_id
  FROM (
    SELECT
      CAST(json_extract(requestparameters, '$.key') AS VARCHAR) AS key
    FROM
      cloudtrail_logs_rx_gbs_datalake_cloud_trail_logs_preprod 
    WHERE
      additionalEventData LIKE '%QueryString%'
      AND NOT (useridentity.arn LIKE '%ADFS-DataDeveloperGeneral%')
      AND NOT (useridentity.arn LIKE '%ADFS-DataConsumerGeneral%')
    ORDER BY eventtime DESC
    
  )
)

SELECT
  cte.athena_id,
  SUBSTRING(useridentity.principalid, (strpos(useridentity.principalid, ':') + 1)) User_id,
  useridentity.sessioncontext.sessionissuer.username User_role,
  useridentity.accountid Account_id,
  SUBSTRING(eventtime, 1, 10) Date_of_download,
  eventsource Source_of_download,
  (CAST(json_extract("additionaleventdata", '$.bytesTransferredOut') AS DOUBLE) / 1024) Size_of_download_in_kb,
  sourceipaddress Source_ip_address,
  useragent user_agent,
  CAST(json_extract(requestparameters, '$.bucketName') AS VARCHAR) bucketName,
  CAST(json_extract(requestparameters, '$.key') AS VARCHAR) key,
  eventversion,
  useridentity.type useridentity_type,
  useridentity.principalid useridentity_principalid,
  useridentity.arn useridentity_arn,
  useridentity.accountid useridentity_accountid,
  useridentity.invokedby useridentity_invokedby,
  useridentity.accesskeyid useridentity_accesskeyid,
  useridentity.username useridentity_username,
  useridentity.sessioncontext.attributes.mfaauthenticated useridentity_mfaauthenticated,
  useridentity.sessioncontext.attributes.creationdate useridentity_creationdate,
  useridentity.sessioncontext.sessionissuer.type useridentity_sessionissuer_type,
  useridentity.sessioncontext.sessionissuer.principalid useridentity_sessionissuer_principalid,
  useridentity.sessioncontext.sessionissuer.arn useridentity_sessionissuer_arn,
  useridentity.sessioncontext.sessionissuer.accountid useridentity_sessionissuer_accountid,
  useridentity.sessioncontext.sessionissuer.username useridentity_sessionissuer_username,
  useridentity.sessioncontext.ec2roledelivery useridentity_ec2roledelivery,
  useridentity.sessioncontext.webidfederationdata useridentity_webidfederationdata,
  eventtime,
  eventsource,
  eventname,
  awsregion,
  sourceipaddress,
  useragent,
  errorcode,
  errormessage,
  requestparameters,
  responseelements,
  CAST(json_extract(additionaleventdata, '$.SignatureVersion') AS VARCHAR) SignatureVersion,
  CAST(json_extract(additionaleventdata, '$.CipherSuite') AS VARCHAR) EventCipherSuite,
  CAST(json_extract(additionaleventdata, '$.bytesTransferredIn') AS VARCHAR) bytesTransferredIn,
  CAST(json_extract(additionaleventdata, '$.AuthenticationMethod') AS VARCHAR) AuthenticationMethod,
  SUBSTRING(additionaleventdata, (strpos(additionaleventdata, '"x-amz-id-2":"') + LENGTH('"x-amz-id-2":"')), strpos(SUBSTRING(additionaleventdata, (strpos(additionaleventdata, '"x-amz-id-2":"') + LENGTH('"x-amz-id-2":"'))), '"')) x_amz_id_2,
  CAST(json_extract(additionaleventdata, '$.bytesTransferredOut') AS VARCHAR) bytesTransferredOut,
  requestid,
  eventid,
  resources,
  eventtype,
  apiversion,
  readonly,
  recipientaccountid,
  serviceeventdetails,
  sharedeventid,
  vpcendpointid,
  tlsdetails.tlsversion,
  tlsdetails.ciphersuite as tlsdetails_ciphersuite,
  tlsdetails.clientprovidedhostheader
FROM
  cloudtrail_logs_rx_gbs_datalake_cloud_trail_logs_preprod
JOIN cte ON 1=1  -- This join condition ensures that every row from Query 1 is joined with every row from Query 2
WHERE ((additionalEventData LIKE '%QueryString%') AND (NOT (useridentity.arn LIKE '%ADFS-DataDeveloperGeneral%')) AND (NOT (useridentity.arn LIKE '%ADFS-DataConsumerGeneral%')))
ORDER BY eventtime DESC
;
