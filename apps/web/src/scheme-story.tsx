import { GridIcon } from './presentation';
import './scheme-story.css';

const contributions = [
  { icon: 'grid', title: '细粒度密态聚合',
    text: '网关按授权选择和聚合密文，统计端恢复群体结果。',
    detail: '区域、类别、时段 · 总和、平均值、报告数', mechanism: '团队自主 PFDAM' },
  { icon: 'shield', title: '群体结果受控发布',
    text: '核对完整分组、上报情况和发布历史，再提供精确统计结果。',
    detail: '至少10个登记计量点 · 跨任务共享发布历史', mechanism: '签名发布决定' },
  { icon: 'receipt', title: '业务对象联合签名',
    text: '授权、回执、结果与发布决定关联，分别核验来源和内容。',
    detail: 'ECDSA与ML-DSA-65同时验证 · SM2增强签名', mechanism: 'SM3快照与审计关联' },
  { icon: 'lock', title: '业务链路混合保护',
    text: '上传与聚合转发链路核对双方身份和实际密钥建立算法。',
    detail: 'X25519 + ML-KEM-768 · TLS内SM4-GCM增强', mechanism: '逐链路运行记录' },
];

export function SchemeStory() {
  return <section className="scheme-story" aria-labelledby="scheme-story-title">
    <header><span className="scheme-story-mark"><GridIcon name="grid" size={31}/></span><div><h3 id="scheme-story-title">让授权贯穿密态协同</h3><p>以团队自主PFDAM方案连接密文计算、结果发布与业务核验。</p></div></header>
    <div className="scheme-story-roles" aria-label="方案在业务流程中的作用">
      {contributions.map(item => <article key={item.title}><span className="scheme-story-icon"><GridIcon name={item.icon} size={23}/></span><h4>{item.title}</h4><p>{item.text}</p><small>{item.detail}</small><span className="scheme-story-mechanism">{item.mechanism}</span></article>)}
    </div>
  </section>;
}
