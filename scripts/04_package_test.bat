REM *****************************
REM      INSTALL ON TEST ORG   
REM *****************************

REM Config
SET testOrg=orgAlias
SET packageVersionId=04tP3000001yPmTtIAK

REM Install the package
sf package:install -p %packageVersionId% --target-org %testOrg% --wait 30

REM Uninstall the package
sf package uninstall --package %packageVersionId% --target-org %testOrg% --wait 30

REM Uninstall the dependencies
sf package uninstall --package %packageVersionId% --target-org %testOrg% --wait 30
