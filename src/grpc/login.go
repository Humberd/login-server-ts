package grpc_login_server

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/opentibiabr/login-server/src/api/models"
	"github.com/opentibiabr/login-server/src/configs"
	"github.com/opentibiabr/login-server/src/database"
	"github.com/opentibiabr/login-server/src/grpc/login_proto_messages"
	"github.com/opentibiabr/login-server/src/logger"
	"github.com/opentibiabr/login-server/src/serviceerrors"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

const DefaultLoginErrorCode = 3
const configurationErrorMessage = "Game world configuration error. Please contact support. Error: %s (LS-%d)."
const livestreamUnavailableMessage = "No active livestream casters found, or livestream login is disabled."
const ClientIPMetadataKey = "x-client-ip"

func (ls *GrpcServer) Login(ctx context.Context, in *login_proto_messages.LoginRequest) (*login_proto_messages.LoginResponse, error) {
	if database.IsLivestreamLogin(in.Email) {
		return ls.loginLivestream(ctx, in.Password)
	}

	acc, err := database.LoadAccount(ctx, in.Email, in.Password, sourceIP(ctx), ls.DB)
	if err != nil {
		return buildLoginErrorResponse(err, false), nil
	}

	if err := configs.ValidateGameServerName(configs.GetGameServerConfigs()); err != nil {
		logger.Error(err)
		configErr := toConfigurationError(err)
		return buildConfigurationErrorResponse(configErr, acc.IsAdmin()), nil
	}

	characters, err := database.LoadPlayers(ls.DB, acc)
	if err != nil {
		return buildLoginErrorResponse(err, acc.IsAdmin()), nil
	}

	sessionKey, err := acc.CreateSession(ctx, ls.DB)
	if err != nil {
		return buildLoginErrorResponse(err, acc.IsAdmin()), nil
	}

	res := login_proto_messages.LoginResponse{
		PlayData: &login_proto_messages.PlayData{
			Characters: characters,
			Worlds:     models.BuildWorldsMessage(configs.GetGameServerConfigs()),
		},
		Session: acc.GetGrpcSession(sessionKey),
	}

	logger.WithFields(logrus.Fields{
		"0": "gRPC",
		"1": "login",
	}).Debug("processed")

	return &res, nil
}

// Only the local HTTP half may name the client; a remote gRPC caller is keyed by its own address.
func sourceIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		host = p.Addr.String()
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if forwarded := md.Get(ClientIPMetadataKey); len(forwarded) > 0 && forwarded[0] != "" {
				return forwarded[0]
			}
		}
	}
	return host
}

func buildLoginErrorResponse(err error, includeAdminHint bool) *login_proto_messages.LoginResponse {
	publicErr, ok := serviceerrors.FromError(err)
	if !ok {
		publicErr = serviceerrors.LoginService(
			serviceerrors.CodeLoginServiceUnavailable,
			"LOGIN_SERVICE_UNAVAILABLE",
			err,
		)
	}

	if publicErr.Cause != nil {
		logger.Error(publicErr)
	}
	if includeAdminHint {
		publicErr = serviceerrors.WithHint(publicErr, serviceerrors.AdminHint(publicErr.Name))
	}

	return &login_proto_messages.LoginResponse{
		Error: &login_proto_messages.Error{
			Code:    uint32(publicErr.Code),
			Message: serviceerrors.MessageWithHint(publicErr),
		},
	}
}

func buildConfigurationErrorResponse(configErr *configs.ConfigurationError, includeAdminHint bool) *login_proto_messages.LoginResponse {
	publicErr := &serviceerrors.PublicError{
		Code:    configErr.Code,
		Name:    configErr.Name,
		Message: fmt.Sprintf(configurationErrorMessage, configErr.Name, configErr.Code),
	}
	if includeAdminHint {
		publicErr = serviceerrors.WithHint(publicErr, serviceerrors.AdminHint(configErr.Name))
	}

	return &login_proto_messages.LoginResponse{
		Error: &login_proto_messages.Error{
			Code:    uint32(configErr.Code),
			Message: serviceerrors.MessageWithHint(publicErr),
		},
	}
}

func toConfigurationError(err error) *configs.ConfigurationError {
	var configErr *configs.ConfigurationError
	if errors.As(err, &configErr) {
		return configErr
	}

	return &configs.ConfigurationError{
		Code:    configs.ConfigErrorCodeUnknown,
		Name:    configs.ConfigErrorUnknown,
		Message: err.Error(),
		Cause:   err,
	}
}

func (ls *GrpcServer) loginLivestream(ctx context.Context, password string) (*login_proto_messages.LoginResponse, error) {
	characters, err := database.LoadLivestreamCasters(ctx, ls.DB)
	if err != nil {
		logger.Error(err)
		if errors.Is(err, database.ErrLivestreamCastersUnavailable) {
			return buildLivestreamUnavailableResponse(), nil
		}
		return nil, err
	}

	if len(characters) == 0 {
		return buildLivestreamUnavailableResponse(), nil
	}

	return &login_proto_messages.LoginResponse{
		PlayData: &login_proto_messages.PlayData{
			Characters: characters,
			Worlds:     models.BuildWorldsMessage(configs.GetGameServerConfigs()),
		},
		Session: buildLivestreamSession(password),
	}, nil
}

func buildLivestreamUnavailableResponse() *login_proto_messages.LoginResponse {
	return &login_proto_messages.LoginResponse{
		Error: &login_proto_messages.Error{
			Code:    DefaultLoginErrorCode,
			Message: livestreamUnavailableMessage,
		},
	}
}

func buildLivestreamSession(password string) *login_proto_messages.Session {
	return &login_proto_messages.Session{
		IsPremium:    false,
		PremiumUntil: 0,
		SessionKey:   database.LivestreamSessionAccount + "\n" + password,
		LastLogin:    0,
	}
}
