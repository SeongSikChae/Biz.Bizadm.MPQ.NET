---
status: done
category: mpq
feature: 프로젝트README
phase: 개발
---

# 프로젝트 README 개발

## 작업 단위 1: README.md

- **대상**: `src/Biz.Bizadm.MPQ.NET/README.md` (신규)
- **선행 단위**: 없음
- **코드 초안** (핵심 골격; 전체 문구는 구현 시 이 흐름을 따름):

~~~~markdown
# Biz.Bizadm.MPQ.NET

Pure .NET library for reading and writing Blizzard MPQ archives...

## Requirements
- .NET 10 (`net10.0`)

## Install
dotnet add package Biz.Bizadm.MPQ.NET

## Quick start
using var archive = MpqArchive.Open("replay.SC2Replay");
using var stream = archive.OpenFile("replay.details");
using var created = MpqArchive.Create("out.mpq");
created.AddFile("file.bin", content);
created.Flush();

## Capabilities
- MPQ v1–v4 / SC2 user data; compression codecs; listfile/attributes; weak signature; patches

## License
MIT. See LICENSE and THIRD-PARTY-NOTICES.md at the repository root.
~~~~

- **검증**: 파일 존재; `# Biz.Bizadm.MPQ.NET`, `## Requirements`, `## Install`, `## Quick start`, `## Capabilities`, `## License` 헤딩; 영문

## 작업 단위 2: csproj PackageReadmeFile

- **대상**: `src/Biz.Bizadm.MPQ.NET/Biz.Bizadm.MPQ.NET.csproj` — `PropertyGroup` / `ItemGroup`
- **선행 단위**: 1
- **코드 초안**:

```xml
<PackageReadmeFile>README.md</PackageReadmeFile>
<!-- ... existing PropertyGroup ... -->
<None Include="README.md" Pack="true" PackagePath="\" />
```

- **검증**: Release `dotnet build --no-incremental` 후 `dotnet pack --no-build`; `.nupkg`에 `README.md` 포함
