package scan

import (
	"testing"
	"time"

	"certrot/model"
	"certrot/node"
	"certrot/store"
)

func TestPredictions(t *testing.T) {
	nd, err := node.New("n-x", t.TempDir(), store.New(), 10*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		mount model.MountMode
		read  model.ReadMode
		want  bool
		layer string
	}{
		{model.MountVolume, model.ReadPoll, true, ""},
		{model.MountVolume, model.ReadWatchDir, true, ""},
		{model.MountVolume, model.ReadPollWatch, true, ""},
		{model.MountVolume, model.ReadOnce, false, "应用层/只读一次"},
		{model.MountVolume, model.ReadWatchFile, false, "应用层/文件监听"},
		{model.MountVolume, model.ReadWatchDirFiltered, false, "应用层/目录事件过滤"},
		{model.MountSubPath, model.ReadPoll, false, "kubelet 挂载层/subPath"},
		{model.MountSubPath, model.ReadWatchDir, false, "kubelet 挂载层/subPath"},
		{model.MountEnv, model.ReadPoll, false, "容器运行时/环境变量"},
		{model.MountEnv, model.ReadOnce, false, "容器运行时/环境变量"},
	}
	for _, tc := range cases {
		c := &model.Container{ID: "x", Node: "n-x", Mount: tc.mount, Read: tc.read,
			PollInterval: 5 * time.Second}
		p := Predict(c, []*node.Node{nd})
		if p.WillUpdate != tc.want {
			t.Errorf("%s/%s: WillUpdate=%v want %v", tc.mount, tc.read, p.WillUpdate, tc.want)
		}
		if !tc.want && p.Layer != tc.layer {
			t.Errorf("%s/%s: Layer=%q want %q", tc.mount, tc.read, p.Layer, tc.layer)
		}
		if tc.want && p.BoundSeconds <= 0 {
			t.Errorf("%s/%s: expected positive delay bound, got %v", tc.mount, tc.read, p.BoundSeconds)
		}
	}
}

func TestUnknownNodeFallsBack(t *testing.T) {
	c := &model.Container{ID: "x", Node: "ghost", Mount: model.MountVolume, Read: model.ReadPoll,
		PollInterval: 5 * time.Second}
	p := Predict(c, nil)
	if !p.WillUpdate || p.BoundSeconds <= 0 {
		t.Fatalf("fallback prediction broken: %+v", p)
	}
}
