package db

import (
	"time"
)

const (
	timeFormart = "2006-01-02 15:04:05"
)

type Time time.Time

type BaseModel struct {
	Id        int64
	CreatedAt Time
	UpdatedAt Time
}

func (t Time) InLocation(locationName string) Time {
	if len(locationName) == 0 {
		locationName = "Asia/Shanghai"
	}
	loc, err := time.LoadLocation(locationName)
	if err != nil {
		loc, _ = time.LoadLocation("Asia/Shanghai") // 默认时区
	}
	return Time(time.Time(t).In(loc))
}

func (t Time) FormatInLocation(locationName string) string {
	return t.InLocation(locationName).String()
}

func (t *Time) UnmarshalJSON(data []byte) (err error) {
	now, err := time.ParseInLocation(`"`+timeFormart+`"`, string(data), time.Local)
	*t = Time(now)
	return
}

func (t Time) MarshalJSON() ([]byte, error) {
	b := make([]byte, 0, len(timeFormart)+2)
	b = append(b, '"')
	b = time.Time(t).AppendFormat(b, timeFormart)
	b = append(b, '"')
	return b, nil
}

func (t Time) String() string {
	return time.Time(t).Format(timeFormart)
}
