---
status: done
category: mpq
feature: 프로젝트README
phase: 방안
---

# 프로젝트 README 방안

## 문제·목표

- 라이브러리 소비자(NuGet/IDE)가 패키지 목적·설치·최소 사용법을 한 문서에서 파악할 수 있어야 한다.
- NuGet 갤러리/패키지 탐색기에 README가 보이도록 프로젝트 README를 패키지에 포함해야 한다.

## 채택 방안

| 항목 | 결정 |
|---|---|
| 언어 | 영어 (공개 API·XML doc과 동일) |
| 역할 | 소비자용: 개요, 요구사항, 설치, 짧은 사용 예, 기능 요약, 라이선스·서드파티 안내 |
| 경로 | `src/Biz.Bizadm.MPQ.NET/README.md` (요청 ReadMe.md → NuGet 관례 `README.md`) |
| 패키징 | csproj `PackageReadmeFile` + `None` Pack (`LICENSE`와 동일 패턴) |

## 비범위

- 저장소 루트 README
- 한국어 병기
- 포맷/압축/서명·패치 상세 개발자 문서
- `docs/` 위키성 확장
