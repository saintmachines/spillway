# 1.0.1 출시 실행 인계

이 branch는 1.0.1 동결 SDK 소스와 배포 workflow를 담습니다. wheel f93d56ec…/sdist77a26f53…를 GitHub release asset으로 받아 검증하고 그 바이트만 PyPI에 보냅니다. 재빌드는 별도 임시 폴더에서 비교하며 업로드 파일을 대체하지 않습니다.

- 소스: FINAL_PROJECT_LOCK.json(cc42dba9…)의 32개 파일 그대로입니다. README(f68ee0e7…)·CHANGELOG(99284e97…)도 동결 바이트입니다. public main/site의 current-version 최소수정은 출시 후 별도 diff이며, 이 태그의 packaged README를 변경하지 않습니다.
- 검증: source32/wheel27/RECORD/sdist 대조, Py3.12.13+hatchling1.33.0+SOURCE_DATE_EPOCH1794873600 재현, Twine7.0.0 strict, 정확한 workflow 무모델 예제를 사용합니다. 역사적12셀 .489와 새 mini 결과·H10은 이 SDK 출시의 새 성능으로 합치지 않습니다.
- OIDC: 공개1.0.0 provenance는 saintmachines/spillway / publish.yml / pypi를 명시했습니다. 현재 PyPI 관리 설정은 조회하지 않았습니다. 기존 filename을 유지하며 GitHub environment의 실제 조회에서는 보호·branch 제한이 없었습니다.

Root가 검토 후 아래 순서로 실행합니다. 이 준비 작업에서는 원격 push/tag/release/dispatch/upload를 하지 않았습니다.

1. 이 branch의 source/diff를 확인해 commit을 확정하고 release/1.0.1을 push합니다.
2. 그 commit에 annotated v1.0.1 tag를 만들고 push합니다.
3. RELEASE_NOTES.md와 기존 동결 wheel/sdist를 사용해 GitHub release를 만듭니다. 실제 tag-object SHA, release ID와 두 asset ID를 조회합니다.
4. publish.yml을 release/1.0.1 ref에서 publish=false로 dispatch하고 verify 성공을 확인합니다.
5. 같은 commit/tag/asset 입력으로 publish=true를 dispatch합니다. 별도 사용자 재확인은 필요하지 않습니다.
6. PyPI1.0.1 JSON과 두 다운로드 SHA를 직접 readback한 뒤 공개 main/site의 최소 current-version patch를 적용합니다.

```sh
gh workflow run publish.yml --repo saintmachines/spillway --ref release/1.0.1 \
  -f publish=false -f expected_commit="$PUBLISH101_COMMIT" \
  -f tag_object_sha="$PUBLISH101_TAG_OBJECT" -f release_id="$PUBLISH101_RELEASE_ID" \
  -f wheel_asset_id="$PUBLISH101_WHEEL_ASSET_ID" -f sdist_asset_id="$PUBLISH101_SDIST_ASSET_ID"
```

검증 후 마지막 명령의 publish 값만 true로 바꿉니다. expected_commit은 branch HEAD와 event SHA가 같아야 하며, tag는 그 commit을 가리키는 annotated object여야 합니다. 모든 asset name/size/digest와 다운로드 SHA가 고정값과 일치해야 합니다. PyPI 권한은 publish job의 pypi environment에서만 요청합니다.
