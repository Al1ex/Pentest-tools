<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Header>
  <t:RequestServerVersion Version="${ExchangeVersion}" />
</soap:Header>
<soap:Body>
  <m:ResolveNames ReturnFullContactData="false" SearchScope="ContactsActiveDirectory">
	<m:UnresolvedEntry>${UserAccount}</m:UnresolvedEntry>
  </m:ResolveNames>
</soap:Body>
</soap:Envelope>
