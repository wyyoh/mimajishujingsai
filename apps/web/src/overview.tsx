import React from 'react';
import { GridIcon } from './presentation';
import './overview.css';

type Scene = { scene_id: string; name: string };
type Role = 'source' | 'gateway' | 'utility';
const sceneDisplay: Record<string, { icon: string; hint: string }> = {
  residential: { icon: 'home', hint: '掌握区域负荷' },
  park: { icon: 'park', hint: '评估需求响应' },
  charging: { icon: 'charging', hint: '查看充电高峰' },
};
const functions = [
  { id: 'SUM', name: '总和' },
  { id: 'AVG', name: '平均值' },
  { id: 'COUNT', name: '报告数' },
];

export function SceneOverview({ scenes, selectedScene, sourceCount, selectedFunction, dataName, locked, onScene, onFunction, onNavigate, onCreate, onData }: {
  scenes: Scene[];
  selectedScene: string;
  sourceCount: number;
  selectedFunction: string;
  dataName: string;
  locked: boolean;
  onScene: (scene: Scene) => void;
  onFunction: (value: string) => void;
  onNavigate: (role: Role) => void;
  onCreate: () => void;
  onData: () => void;
}) {
  return <section className="overview-board" aria-labelledby="overview-title">
    <div className="overview-heading">
      <div className="overview-intro"><h3 id="overview-title">读数源侧加密，负荷按需汇总</h3><p>团队自主PFDAM，让业务授权进入密文计算。</p></div>
      <div className="overview-actions">
        <button className="v41-secondary" onClick={onData}>查看数据</button>
        <button className="v41-primary" onClick={onCreate}><GridIcon name="run" size={15}/>创建协同任务</button>
      </div>
    </div>

    <div className="overview-scenes" role="group" aria-label="选择业务场景">
      {scenes.map(scene => {
        const display = sceneDisplay[scene.scene_id];
        return <button key={scene.scene_id} aria-label={scene.name} aria-pressed={selectedScene === scene.scene_id} disabled={locked} onClick={() => onScene(scene)}>
          <span className="overview-scene-icon"><GridIcon name={display?.icon || 'grid'} size={24}/></span>
          <span><strong>{scene.name}</strong><small>{display?.hint}</small></span>
          <span className="overview-scene-choice" aria-hidden="true">{selectedScene === scene.scene_id && <GridIcon name="check" size={11}/>}</span>
        </button>;
      })}
    </div>

    <figure className="overview-network" aria-label={`${sourceCount}个数据源、聚合网关与统计端的密文处理流程`}>
      <figcaption>密态协同路径<span>流程示意</span></figcaption>
      <div className="overview-source-column">
        <div className="overview-source-stack" data-multi={sourceCount > 1}>
          {Array.from({ length: sourceCount }, (_, index) => <button key={index} aria-label={`查看数据源${index + 1}`} onClick={() => onNavigate('source')}>
            <GridIcon name="source" size={19}/><span>{`源 ${index + 1}`}</span>
          </button>)}
        </div>
        <span className="overview-node-caption"><strong>数据源</strong><small>明细在源侧加密</small></span>
      </div>
      <div className="overview-wire" aria-hidden="true"><span>密文报告</span><i/><GridIcon name="lock" size={13}/></div>
      <button className="overview-hub" onClick={() => onNavigate('gateway')} aria-label="查看PFDAM密码能力">
        <span className="overview-hub-core"><GridIcon name="grid" size={31}/><span>PFDAM</span></span>
        <span className="overview-node-caption"><strong>聚合网关</strong><small>按授权聚合密文</small></span>
      </button>
      <div className="overview-wire" aria-hidden="true"><span>密文与回执</span><i/><GridIcon name="receipt" size={14}/></div>
      <button className="overview-utility" onClick={() => onNavigate('utility')} aria-label="查看统计结果">
        <span className="overview-utility-core"><GridIcon name="chart" size={31}/></span>
        <span className="overview-node-caption"><strong>统计端</strong><small>核验后受控发布</small></span>
      </button>
    </figure>

    <div className="overview-controls">
      <div className="overview-functions" role="group" aria-label="选择统计方式"><span>统计方式</span>{functions.map(item => <button key={item.id} aria-label={`${item.name}（${item.id}）`} aria-pressed={selectedFunction === item.id} disabled={locked} onClick={() => onFunction(item.id)}>{item.name}<small>{item.id}</small></button>)}</div>
      <button className="overview-crypto-link" onClick={() => onNavigate('gateway')}><GridIcon name="shield" size={16}/>联合签名与混合通信</button>
    </div>
    <div className="overview-foot"><span><GridIcon name="source" size={14}/>{dataName}</span><span>{sourceCount}个数据源进程，同机运行</span></div>
  </section>;
}
