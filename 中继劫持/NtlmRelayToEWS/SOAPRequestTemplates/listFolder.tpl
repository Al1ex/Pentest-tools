<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Header>
  <t:RequestServerVersion Version="${ExchangeVersion}" />
</soap:Header>
<soap:Body>
  <m:FindItem Traversal="Shallow">
	<m:ItemShape>
	  <t:BaseShape>AllProperties</t:BaseShape>
	</m:ItemShape>
	<m:IndexedPageItemView MaxEntriesReturned="1000" Offset="0" BasePoint="Beginning" />
	<m:ParentFolderIds>
	  <t:DistinguishedFolderId Id="${Folder}" />
	</m:ParentFolderIds>
  </m:FindItem>
</soap:Body>
</soap:Envelope>
