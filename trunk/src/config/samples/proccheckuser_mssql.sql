USE [showcase]
GO

CREATE PROCEDURE [dbo].[checkUserIP]
	@userlogin varchar(256),
	@userip varchar(16),
	@error_mes varchar(512) output
AS
BEGIN

set @error_mes =  + 'Пользователь '+@userlogin+' не прошел проверку по IP '+@userip;

RETURN 1;

END

GO