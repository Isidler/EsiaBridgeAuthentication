# EsiaBridgeAuthentication
OWIN OAuth Provider ESIA-Bridge

Библиотека для авторизации через госуслуги ESIA-Bridge

Использование:
1. Добавить в Startup
```csharp
using EsiaBridgeAuthentication;
```
2. Добавить в метод Startup.Configuration

```csharp
app.UseEsiaBirdgeAuthentication(new EsiaBridgeAuthenticationOptions(
    schema: "http", 
    url: "{dns адрес вашего сервиса например: api.example.ru}", 
    port: "9000"
));
```
Не забудьте, что dns адрес вашего сервиса должен быть в одном домене что и сервис ESIA-Bridge. Подробнее смотрите в документации к самому ESIA-Bridge.
Документация ESIA-Bridge: https://identityblitz.ru/products/esia-bridge/documentation/

Тестировался на проекте web api. 

По всем недочетам пишите, буду исправлять.
