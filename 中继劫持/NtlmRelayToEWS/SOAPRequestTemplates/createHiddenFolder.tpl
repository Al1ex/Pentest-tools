<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Header>
  <t:RequestServerVersion Version="${ExchangeVersion}" />
</soap:Header>
<soap:Body>
  <m:CreateFolder>
	<m:ParentFolderId>
	  <t:DistinguishedFolderId Id="${ParentFolder}" />
	</m:ParentFolderId>
	<m:Folders>
	  <t:Folder>
		<t:FolderClass>IPF.Note</t:FolderClass>
		<t:DisplayName>microsoft</t:DisplayName>
		<t:ExtendedProperty>
		  <t:ExtendedFieldURI PropertyTag="4340" PropertyType="Boolean" />
		  <t:Value>true</t:Value>
		</t:ExtendedProperty>
	  </t:Folder>
	</m:Folders>
  </m:CreateFolder>
</soap:Body>
</soap:Envelope>
