<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Header>
  <t:RequestServerVersion Version="${ExchangeVersion}" />
</soap:Header>
<soap:Body>
  <m:AddDelegate>
	<m:Mailbox>
	  <t:EmailAddress>${TargetAddress}</t:EmailAddress>
	</m:Mailbox>
	<m:DelegateUsers>
	  <t:DelegateUser>
		<t:UserId>
		  <t:PrimarySmtpAddress>${DelegateAddress}</t:PrimarySmtpAddress>
		</t:UserId>
		<t:DelegatePermissions>
		  <t:CalendarFolderPermissionLevel>None</t:CalendarFolderPermissionLevel>
		  <t:TasksFolderPermissionLevel>None</t:TasksFolderPermissionLevel>
		  <t:InboxFolderPermissionLevel>Editor</t:InboxFolderPermissionLevel>
		  <t:ContactsFolderPermissionLevel>None</t:ContactsFolderPermissionLevel>
		  <t:NotesFolderPermissionLevel>None</t:NotesFolderPermissionLevel>
		  <t:JournalFolderPermissionLevel>None</t:JournalFolderPermissionLevel>
		</t:DelegatePermissions>
		<t:ReceiveCopiesOfMeetingMessages>false</t:ReceiveCopiesOfMeetingMessages>
		<t:ViewPrivateItems>false</t:ViewPrivateItems>
	  </t:DelegateUser>
	</m:DelegateUsers>
	<m:DeliverMeetingRequests>DelegatesAndSendInformationToMe</m:DeliverMeetingRequests>
  </m:AddDelegate>
</soap:Body>
</soap:Envelope>
