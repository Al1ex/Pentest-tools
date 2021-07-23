<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Header>
  <t:RequestServerVersion Version="${ExchangeVersion}" />
</soap:Header>
<soap:Body>
  <m:UpdateFolder>
	<m:FolderChanges>
	  <t:FolderChange>
		<t:FolderId Id="${FolderId}" ChangeKey="${ChangeKey}" />
		<t:Updates>
		  <t:SetFolderField>
			<t:ExtendedFieldURI PropertyTag="14047" PropertyType="Binary" />
			<t:Folder>
			  <t:ExtendedProperty>
				<t:ExtendedFieldURI PropertyTag="14047" PropertyType="Binary" />
				<t:Value>${HomePage}</t:Value>
			  </t:ExtendedProperty>
			</t:Folder>
		  </t:SetFolderField>
		</t:Updates>
	  </t:FolderChange>
	</m:FolderChanges>
  </m:UpdateFolder>
</soap:Body>
</soap:Envelope>
