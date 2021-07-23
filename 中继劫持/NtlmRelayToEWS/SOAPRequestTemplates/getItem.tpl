<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Header>
  <t:RequestServerVersion Version="${ExchangeVersion}" />
</soap:Header>
<soap:Body>
  <m:GetItem>
	<m:ItemShape>
	  <t:BaseShape>IdOnly</t:BaseShape>
	  <t:AdditionalProperties>
		<t:FieldURI FieldURI="item:MimeContent" />
	  </t:AdditionalProperties>
	</m:ItemShape>
	<m:ItemIds>
	  <t:ItemId Id="${Id}" ChangeKey="${ChangeKey}" />
	</m:ItemIds>
  </m:GetItem>
</soap:Body>
</soap:Envelope>
