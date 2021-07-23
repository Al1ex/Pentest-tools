<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Header>
  <t:RequestServerVersion Version="${ExchangeVersion}" />
</soap:Header>
<soap:Body>
  <m:CreateItem MessageDisposition="SendOnly">
	<m:Items>
	  <t:Message>
		<t:Subject>${Subject}</t:Subject>
		<t:Body BodyType="HTML">${Message}</t:Body>
		<t:ToRecipients>
			${DestAddressBlock}
		</t:ToRecipients>
	  </t:Message>
	</m:Items>
  </m:CreateItem>
</soap:Body>
</soap:Envelope>

