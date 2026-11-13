package catalog

import (
	"authgo/internal/apperror"
	"authgo/internal/channel"

	"context"

	"time"
)

func (s *Service) RotateGateway(ctx context.Context, hours int) (channel.Key, error) {
	if hours < 1 || hours > 8760 {
		return channel.Key{}, apperror.Invalid("过渡时长需为1至8760小时")
	}
	return s.channel.Rotate(ctx, time.Duration(hours)*time.Hour)
}
func (s *Service) GatewayInfo(ctx context.Context) (channel.Key, error) {
	return s.channel.Current(ctx)
}
