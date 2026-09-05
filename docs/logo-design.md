# PolyGP Logo 设计稿

## 项目与用途

PolyGP 是通过网页管理的 VPN 容器，主要操作是登录、完成认证、连接代理和管理设备标识。Logo 用于 GitHub 中英文 README 的项目页首；名称仍用可选中、可搜索的正文显示。

## 设计方向：连接通道

采用简洁的几何通道图形：蓝灰色的开放轮廓带有 P / G 的字母联想，一条青绿色短路径进入图形内部，代表从本地应用到 VPN 的连接。粗细一致的线条、清楚的留白和圆角与控制页面的视觉语言一致。

图形应在小尺寸下容易辨认，不依赖细线或纹理。它是 PolyGP 的独立标识，不使用大学校徽、官方 VPN 标志或 jj 的 Logo。

| 项目 | 设计要求 |
| --- | --- |
| 主色 | 蓝灰 `#58758A`，对应面板导航的色调 |
| 辅色 | 青绿 `#39AFA4`，表示连接路径 |
| 形状 | 开放的几何通道，轻微 P / G 字母联想 |
| 背景 | 透明，不绘制背景棋盘格 |
| 留白 | 图形四周约 12% |
| 文字 | 图像不包含文字；README 单独显示 PolyGP |
| 避免 | 盾牌、锁、地球、校徽、渐变、阴影、3D、设备样机 |

## 生成提示词

使用内置 image_gen，生成单个 Logo 图形。以下为实际使用的提示词：

```text
Use case: logo-brand.
Asset type: an original logo symbol for the PolyGP open-source VPN control panel, to be used above a text heading in a GitHub README.
Create one polished, minimal, flat geometric symbol of an open connection portal. A bold slate-blue rounded angular path should subtly suggest a P/G monogram through clean negative space. A short teal path enters the opening, suggesting a local application connecting to a VPN. Prioritize a distinctive, simple silhouette over literal lettering. Consistent substantial stroke weight, carefully balanced corners and negative space, legible at 48 pixels.
Color palette: slate blue #58758A and teal #39AFA4 only. Solid fills, flat vector-like edges. No gradients or shadows.
Composition: one centered standalone symbol on a genuinely transparent background, square 1024x1024 canvas, about 12 percent clear space on each edge. Preserve alpha transparency; do not draw a checkerboard.
No text, wordmark, slogan, labels, watermark, grid, mockup, border or presentation sheet. No shield, padlock, globe, university crest, or reference to any existing logo. Return one finished symbol, not alternatives.
```

## 生成后的修整

首版在青绿色路径与蓝灰色轮廓相交处出现了零散边缘，补充以下编辑提示词，保留构图并清理边缘：

```text
Keep the exact same logo geometry, scale, placement and two colors. Clean up the rendering only: remove every stray cyan fragment, rough pixel, fringe and speckle along all edges, especially around the crossing of the teal arrow and the left slate-blue stroke. Make all filled areas perfectly flat, uniform solid colors (#58758A and #39AFA4), with clean antialiased vector-like contours. The gaps around the arrow must be completely transparent and neat. Preserve a genuinely transparent background and the existing canvas size. No gradients, texture, shadow, extra objects or text.
```

## 文件与使用

第二版清理了边缘，但背景被绘制成棋盘格，因此追加背景提取：

```text
Use case: background-extraction. Remove the entire gray and white checkerboard background from this logo, including inside the portal and the narrow gaps around the teal arrow. It is a printed background that must be deleted, not retained. Output a PNG with an actual alpha channel: all background pixels must have alpha 0. Preserve only the slate-blue and teal logo shapes with clean antialiased edges. Preserve the symbol geometry, colors and canvas size. Do not draw a new background, checkerboard, white rectangle, shadow, gradient, or any text.
```

透明提取仍有局部边缘杂色。因此 README 采用纯白背景版本，保留透明版作为后续制作矢量图时的参考。最后的编辑提示词：

```text
Preserve the exact logo symbol geometry, placement and proportions from the reference. Replace the entire checkerboard background with perfectly uniform pure white #FFFFFF, including inside the symbol and all narrow gaps. This final deliverable must have an opaque white background, not transparency and not a checkerboard. Render the logo shapes as uniform flat solid slate blue #58758A and teal #39AFA4 with perfectly clean antialiased edges. Remove all texture, gradients, pixel fringes and color speckles. Do not change the shape or add any text, shadow or objects. Return one square finished logo on white.
```

- 生成结果：[`assets/polygp-logo.png`](assets/polygp-logo.png)，用于 README 的纯白背景 PNG，不是矢量源文件。
- 透明参考版：[`assets/polygp-logo-transparent.png`](assets/polygp-logo-transparent.png)，局部边缘仍需在矢量化时整理。
- README 建议显示宽度 128–160 px，保留图片内的留白，不拉伸变形。
- 中英文 README 使用同一份图片，名称和介绍用各自语言的 Markdown 编写。
- 后续如需印刷或大尺寸应用，可根据选定图形另行制作 SVG，并检查小尺寸和单色显示。

## README 排版参考

参考 [jj-vcs/jj 的 README](https://github.com/jj-vcs/jj)：项目标题下提供简短导航，依次介绍项目、入门方式、功能和参与开发的方法。仅参考信息结构；文案与图形均为 PolyGP 单独编写。
