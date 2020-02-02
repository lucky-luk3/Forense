SELECT
COUNT(EventID) AS TotalLogonSuccessfull,
TO_LOWERCASE(EXTRACT_TOKEN(Strings,11,'|')) AS SourceAddress,
TO_LOWERCASE(EXTRACT_TOKEN(Strings,0,'|')) AS User,
TO_LOWERCASE(EXTRACT_TOKEN(Strings,5,'|')) AS WorkStation,
TO_LOWERCASE(EXTRACT_TOKEN(Strings,7,'|')) AS CallerDomain
INTO SecEvtLogonCOunt.csv
FROM security
WHERE(EventID IN (4624;4648;4778))
AND(SourceAddress IS NOT NULL)
GROUP BY SourceAddress,User,WorkStation,CallerDomain
ORDER BY TotalLogonSuccessfull ASC