unit megaplanapi;

interface

uses Classes, SysUtils, httpsend, synacode, ssl_openssl, synautil;

const
  LF = #$0a;
  APIVersion = 'BumsTaskApiV01';
  cErrString = 'Ошибка сервера [%d - %s]';

type
  TMegaplanRequest = class
  private
    FAccessID  : string;
    FSecretKey : string;
    FData      : TStringStream;
    FProto     : string;
    FHost      : string;
    procedure SetData(Str: string);
    function GetData:string;
    function CalcSignarure(const Method, URL: string; Date: String): string;
  public
    constructor Create(Host, Proto: string);
    destructor Destroy;

    function Login(Username, Password: string): string;
    function Get(const URL: string):string;
    function Post(const URL:string):string;
    property Data: string read GetData write SetData;
end;

Function GetJSONValue(JSONString, JSONParam: string): string;
procedure DebugMsg(const Msg: String);
implementation

uses XMLDoc, ActiveX, XMLDom, Windows;


procedure DebugMsg(const Msg: String);
begin
    OutputDebugString(PChar(Msg))
end;

{ TMegaplanRequest }

function TMegaplanRequest.CalcSignarure(const Method, URL: string; Date: String): string;
var BaseString: TStringStream;
    HMACsig,RFCDate,str: String;
begin
  BaseString:=TStringStream.Create;
  try
    BaseString.WriteString(Method+LF);//метод
    if FData.Size=0 then
      BaseString.WriteString(LF)//ContentMD5 отсутствует
    else
      BaseString.WriteString(StrToHex(MD5(FData.DataString))+LF);

    if UpperCase(Method)='POST' then
      BaseString.WriteString('application/x-www-form-urlencoded'+LF)
      //BaseString.WriteString(LF)
    else
      BaseString.WriteString(LF);//Content-Type отсутствует

    BaseString.WriteString(Date+LF);
    BaseString.WriteString(URL);//HOST+URI
    HMACsig:=HMAC_SHA1(BaseString.DataString,FSecretKey);//зашифровали по HMAC-SHA1
    Result:=EncodeBase64((StrToHex(HMACsig)));//перевели в HEX и шифроали по Base64

    str:=BaseString.DataString;
    str:=StringReplace(str, #13, '#13', [rfReplaceAll]);
    str:=StringReplace(str, #10, '#10', [rfReplaceAll]);

  finally
    BaseString.Free;
  end;
end;

constructor TMegaplanRequest.Create(Host, Proto: string);
begin
  inherited Create;
  FHost := Host;
  FProto := Proto;
  FData:=TStringStream.Create;
end;

destructor TMegaplanRequest.Destroy;
begin
  FData.Free;
  inherited Destroy;
end;

Function Min(i,j:integer): integer;
begin
  if i<j then result:=i else result:=j;
end;

Function GetJSONValue(JSONString, JSONParam: string): string;
var
  i1, i2:integer;
  value: string;
  JSONParam_int: string;
begin
  JSONParam_int:='"'+JSONParam+'":';
  i1:=pos(JSONParam_int, JSONString);
  if i1=0 then
  begin
    result:='';
    exit;
  end;

  i1:=i1+length(JSONParam_int);
  i2:=min(pos(',', JSONString, i1), pos('}', JSONString, i1));
  value:=copy(JSONString, i1, i2-i1);
  if value[1]='"' then
    value:=copy(value, 2, length(value)-2);
  result := value;
end;

function TMegaplanRequest.Login(Username, Password: string):string;
var PasswordMD5 : string;
    DataStream: TstringStream;
    URL:string;
begin
  Result:='Login failed (internal reason)';
  PasswordMD5:=StrToHex(MD5(Password));
  DataStream:=TStringStream.Create;
  URL := 'https://'+FHost+'/BumsCommonApiV01/User/authorize.api?Login='+Username+'&Password='+PasswordMD5;
  DebugMsg(URL);
  try
    with THTTPSend.Create do
      begin
        Headers.Add('Accept: application/json');
        if HTTPMethod('GET', URL) then
          DataStream.LoadFromStream(Document)
        else
          Exception.Create(Format(cErrString,[ResultCode,ResultString]));

        DebugMsg('Login response "'+DataStream.DataString+'"');

        //Parse
        if Pos('{"status":{"code":"ok","message":null}', DataStream.DataString) >0 then
        begin
          FAccessId  :=GetJSONValue(DataStream.DataString, 'AccessId');
          FSecretKey :=GetJSONValue(DataStream.DataString, 'SecretKey');
          DebugMsg('Key: '+FAccessId+':'+FSecretKey);
          Result:='ok';
        end
        else
          begin
            DebugMsg('Key: failed to login, reason: "'+DataStream.DataString+'"');
            Result:=DataStream.DataString;
          end;
        DebugMsg(Format('LastError: %d(%s)',[Sock.LastError,Sock.LastErrorDesc]));
        DebugMsg(Format('SSL Error: %d(%s)',[Sock.SSL.LastError,Sock.SSL.LastErrorDesc]));
      end;
  finally
    DataStream.Free;
  end;
end;

function TMegaplanRequest.Get(const URL: string): string;
var intURI:string;
    Date: string;
    DataStream: TstringStream;
begin
  Date:=Rfc822DateTime(Now);
  //Date:='Wed, 25 May 2011 16:50:58 +0400';
  DataStream:=TStringStream.Create;
try
  with THTTPSend.Create do
    begin
      Headers.Add('Date: '+Date);
      Headers.Add('X-Authorization: '+FAccessID+':'+CalcSignarure('GET',FHost+URL,Date));
      Headers.Add('Accept: application/json');
      if HTTPMethod('GET',FProto+'://'+FHost+URL) then
        DataStream.LoadFromStream(Document)
      else
        Exception.Create(Format(cErrString,[ResultCode,ResultString]));
    end;
  Result:=DataStream.DataString;
finally
  DataStream.Free;
end;
end;

function TMegaplanRequest.GetData: string;
begin
  Result:=FData.DataString
end;

function TMegaplanRequest.Post(const URL: string): string;
var
    Date: string;
    H:TStringList;
    DataStream: TstringStream;
begin
  Date:=Rfc822DateTime(Now);
  DataStream:=TStringStream.Create;
try
  with THTTPSend.Create do
    begin
      UserAgent := 'SdfApi_Request';
      MimeType  := 'application/x-www-form-urlencoded';
      Protocol  := '1.1';

      Headers.Add('Date: '+Date);
      if FData.Size>0 then
        Headers.Add('Content-MD5: '+StrToHex(MD5(FData.DataString)));
      Headers.Add('X-Authorization: '+FAccessID+':'+CalcSignarure('POST',FHost+URL,Date));
      Headers.Add('Accept: application/json');

      FData.Position:=0;
      Document.LoadFromStream(FData);
      if HTTPMethod('POST', FProto+'://'+FHost+URL) then
        DataStream.LoadFromStream(Document)
      else
        Exception.Create(Format(cErrString,[ResultCode,ResultString]));
    end;
  Result:=DataStream.DataString;
finally
  DataStream.Free;
end;
end;

procedure TMegaplanRequest.SetData(Str: string);
begin
  FData.Clear;
  FData.WriteString(Str);
end;

end.
