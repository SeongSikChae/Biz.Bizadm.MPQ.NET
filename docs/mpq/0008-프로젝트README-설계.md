---
status: done
category: mpq
feature: 프로젝트README
phase: 설계
---

# 프로젝트 README 설계

## 구조

| 산출물 | 역할 |
|---|---|
| `src/Biz.Bizadm.MPQ.NET/README.md` | 영문 소비자 README 본문 |
| `Biz.Bizadm.MPQ.NET.csproj` | `PackageReadmeFile` + Pack 항목 |

## README 섹션

1. **Title + one-liner** — `Biz.Bizadm.MPQ.NET` / MPQ archive read/write for .NET 10
2. **Requirements** — `net10.0`
3. **Install** — `dotnet add package Biz.Bizadm.MPQ.NET`
4. **Quick start** — 짧은 C# 예: `MpqArchive.Open` + `OpenFile` 또는 `Entries`; `Create` + `AddFile`
5. **Capabilities** — 한 줄 bullet: formats v1–v4 / SC2 user data; compression codecs; listfile/attributes; weak signature; patch archives
6. **License** — MIT; 상대 링크로 저장소 루트 `LICENSE`, `THIRD-PARTY-NOTICES.md` (패키지 뷰에서는 링크가 깨질 수 있으므로 파일명도 본문에 명시)

## csproj

```xml
<PackageReadmeFile>README.md</PackageReadmeFile>
...
<None Include="README.md" Pack="true" PackagePath="\" />
```

기존 `LICENSE` Pack·`GenerateDocumentationFile` 등은 유지.

## 의존·결정

- 의존 NuGet: SharpCompress (README에 런타임 의존 상세 나열 불필요; THIRD-PARTY-NOTICES로 위임)
- Quick start API: `MpqArchive.Open` / `Create` / `OpenFile` / `AddFile` / `Entries` (공개 API 변경 없음)
